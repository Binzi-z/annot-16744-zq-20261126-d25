# -*- coding: utf-8 -*-
"""保管链服务：交接 / 撤销 / 恢复 / 批准代轮换 / 冲突证书 / 缺段回填。

线程模型
--------
服务内有一把可重入锁，:class:`threading.Barrier` 同步下的两个真实线程
可以并发调用；锁保证每个包的“分配序号 -> 追加封签 -> 更新状态”是
临界区。验证器是只读的，不经过这把锁。

故障模型
--------
* ``receipt_lost``：封签已经 fsync 进日志（文件持久化），但服务在写
  回执/状态前崩溃 -> 重启后 :meth:`recover` 从日志重建状态，不会重复
  追加，也不会丢失已承诺事件。
* 旧代封签迟到：:meth:`rotate_generation` 推进批准代之后，带着旧
  ``approval_gen`` 的封签再到达，:meth:`ingest` 一律拒绝并出具说明，
  历史记录不受影响。
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Mapping

from . import crypto, model
from .storage import FileStore


class CustodyError(Exception):
    """保管服务业务错误基类。"""


class InvalidRecordError(CustodyError):
    """封签自洽校验失败（摘要、结构或双签核）。"""


class StaleGenerationError(CustodyError):
    """迟到的旧代封签：记录的批准代小于当前批准代。"""


class ConflictError(CustodyError):
    """同编号异摘要冲突，证书路径随异常返回。"""

    def __init__(self, message: str, certificate_path: str):
        super().__init__(message)
        self.certificate_path = certificate_path


class CustodyService:
    def __init__(self, store: FileStore, root_secret: str = "synthetic-root-secret"):
        self.store = store
        self.keys = crypto.signer_keys(root_secret)
        self._lock = threading.RLock()
        self.state = store.load_state()
        self.recover()

    # ---- 内部工具 ------------------------------------------------------------

    def _pkg_state(self, package_id: str) -> dict[str, Any]:
        packages = self.state.setdefault("packages", {})
        return packages.setdefault(
            package_id, {"next_seq": 1, "last_digest": crypto.GENESIS_DIGEST}
        )

    def _new_nonce(self) -> str:
        return uuid.uuid4().hex

    def _sign(self, record_digest: str) -> dict[str, str]:
        return {
            signer: crypto.sign_digest(record_digest, signer, self.keys[signer])
            for signer in crypto.SIGNERS
        }

    def _persist(self, package_id: str, envelope: dict[str, Any]) -> None:
        """先追加日志并 fsync，再原子更新状态（崩溃安全顺序）。"""
        self.store.append_log(package_id, envelope)
        self.store.save_state(self.state)

    # ---- 合成物证 ------------------------------------------------------------

    def materialize(self, package_id: str, files: Mapping[str, bytes]) -> None:
        """在实际文件目录写出合成物证文件。"""
        with self._lock:
            self.store.ensure_package(package_id)
            for rel_path, data in files.items():
                self.store.write_file(package_id, rel_path, data)

    # ---- 正常交接 / 撤销 -----------------------------------------------------

    def handoff(
        self,
        package_id: str,
        event_type: str = model.HANDOFF,
        *,
        manifest: Mapping[str, str] | None = None,
        receipt_lost: bool = False,
    ) -> dict[str, Any]:
        """执行一次交接（或撤销），返回回执。

        manifest 为 None 时从磁盘实际目录实时扫描，保证封签绑定的是
        实际文件目录而非调用方的口头声明。

        receipt_lost=True 模拟“文件持久化但回执丢失”：日志已 fsync，
        状态不更新且不返回回执，仿佛进程在两步之间崩溃。
        """
        with self._lock:
            pkg = self._pkg_state(package_id)
            seq = pkg["next_seq"]
            body = model.build_body(
                package_id=package_id,
                seq=seq,
                event_type=event_type,
                prev_digest=pkg["last_digest"],
                manifest=manifest
                if manifest is not None
                else self.store.manifest_from_disk(package_id),
                approval_gen=self.state["generation"],
                nonce=self._new_nonce(),
                signoffs={},  # 占位，下面补双签
            )
            # 两位签核人对“无签核本体”的摘要分别签名。
            payload = model.signing_payload(body)
            body["signoffs"] = self._sign(payload)
            # 外壳摘要覆盖完整本体（含双签核），一次定稿。
            record_digest = crypto.digest_json(body)
            envelope = model.wrap(body)

            # 1) 封签先落盘并 fsync。
            self.store.append_log(package_id, envelope)
            if receipt_lost:
                # 状态/回执均未更新 —— 模拟崩溃，等待 recover()。
                return {"status": "LOST_BEFORE_RECEIPT", "seq": seq}

            # 2) 再推进内存状态并原子落盘。
            pkg["next_seq"] = seq + 1
            pkg["last_digest"] = record_digest
            self.store.save_state(self.state)
            return {
                "status": "COMMITTED",
                "package_id": package_id,
                "seq": seq,
                "event_type": event_type,
                "digest": record_digest,
                "approval_gen": self.state["generation"],
            }

    def revoke(self, package_id: str, **kwargs: Any) -> dict[str, Any]:
        """撤销也是一条链上事件（REVOKE），同样绑定前一摘要与双签核。"""
        return self.handoff(package_id, model.REVOKE, **kwargs)

    # ---- 批准代 --------------------------------------------------------------

    def rotate_generation(self) -> int:
        """推进批准代；此后旧代封签再到达即判定为迟到。"""
        with self._lock:
            self.state["generation"] += 1
            self.store.save_state(self.state)
            return self.state["generation"]

    @property
    def generation(self) -> int:
        return self.state["generation"]

    # ---- 崩溃恢复 ------------------------------------------------------------

    def recover(self) -> dict[str, Any]:
        """从只追加日志重建状态（幂等）。

        重新扫描每个包的日志，按 seq 重放；校验失败或链断裂的记录
        不进入已承诺状态，留给只读验证器出具冲突/缺段结论。
        """
        recovered: dict[str, dict[str, Any]] = {}
        for package_id in self.store.list_packages():
            envelopes = self.store.read_log(package_id)
            last_digest = crypto.GENESIS_DIGEST
            next_seq = 1
            for envelope in envelopes:
                ok, _ = model.check_envelope_integrity(envelope)
                if not ok:
                    break
                body = envelope["body"]
                sig_ok, _ = model.check_signoffs(envelope, self.keys)
                if not sig_ok or body["prev_digest"] != last_digest:
                    break
                if body["seq"] != next_seq:
                    break
                last_digest = envelope["digest"]
                next_seq += 1
            recovered[package_id] = {
                "next_seq": next_seq,
                "last_digest": last_digest,
            }
        with self._lock:
            self.state["generation"] = self.state.get("generation", 0)
            self.state["packages"] = recovered
            self.store.save_state(self.state)
        return recovered

    # ---- 外部封签到达（冲突 / 迟到旧代 / 缺段回填）--------------------------

    def ingest(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """接收一条外部到达的封签并分类处理。"""
        with self._lock:
            ok, problems = model.check_envelope_integrity(envelope)
            if not ok:
                raise InvalidRecordError("; ".join(problems))
            sig_ok, sig_problems = model.check_signoffs(envelope, self.keys)
            if not sig_ok:
                raise InvalidRecordError("; ".join(sig_problems))

            body = envelope["body"]
            package_id = body["package_id"]
            seq = body["seq"]
            digest = envelope["digest"]

            # 迟到的旧代封签：当前批准代已被轮换推进。
            if body["approval_gen"] < self.state["generation"]:
                raise StaleGenerationError(
                    f"旧代封签迟到: 记录代={body['approval_gen']} "
                    f"当前代={self.state['generation']} (package={package_id} seq={seq})"
                )

            self.store.ensure_package(package_id)
            envelopes = self.store.read_log(package_id)
            existing = {e["body"]["seq"]: e for e in envelopes}
            pkg = self._pkg_state(package_id)

            # 同编号且同摘要：幂等重复，直接返回既有回执。
            if seq in existing:
                if existing[seq]["digest"] == digest:
                    return {
                        "status": "DUPLICATE_OK",
                        "package_id": package_id,
                        "seq": seq,
                        "digest": digest,
                    }
                # 同编号异摘要 -> 冲突证书（缺段绝不走这条路径）。
                certificate = self._conflict_certificate(
                    package_id, seq, existing[seq], envelope
                )
                path = self.store.write_conflict(package_id, certificate)
                raise ConflictError(
                    f"同编号异摘要冲突 package={package_id} seq={seq}: "
                    f"已承诺 {existing[seq]['digest'][:12]}… vs 到达 {digest[:12]}…",
                    path,
                )

            # 日志中已存在更大序号 => 这是迟到的先前事件，走回填重排，
            # 而不是简单追加（否则日志顺序里缺口依然存在）。
            if envelopes and max(existing) > seq:
                return self._backfill(package_id, envelope, envelopes)

            # 新序号：恰好接在已承诺前缀之后 -> 正常追加。
            if seq == pkg["next_seq"] and body["prev_digest"] == pkg["last_digest"]:
                self.store.append_log(package_id, envelope)
                pkg["next_seq"] = seq + 1
                pkg["last_digest"] = digest
                self.store.save_state(self.state)
                return {
                    "status": "COMMITTED",
                    "package_id": package_id,
                    "seq": seq,
                    "digest": digest,
                }

            if seq < pkg["next_seq"]:
                return self._backfill(package_id, envelope, envelopes)

            # 跳号（缺段未补却想续在后面）：明确报缺段，而非冲突。
            raise CustodyError(
                f"缺段: package={package_id} 已承诺到 seq={pkg['next_seq'] - 1}，"
                f"到达 seq={seq}，需先补齐中间事件"
            )

    def make_seal(
        self,
        package_id: str,
        seq: int,
        prev_digest: str,
        manifest: Mapping[str, str],
        approval_gen: int,
        event_type: str = model.HANDOFF,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        """按当前签核规则构造一条完整封签（演示旧代封签/迟到事件用）。"""
        body = model.build_body(
            package_id=package_id,
            seq=seq,
            event_type=event_type,
            prev_digest=prev_digest,
            manifest=dict(manifest),
            approval_gen=approval_gen,
            nonce=nonce or self._new_nonce(),
            signoffs={},
        )
        payload = model.signing_payload(body)
        body["signoffs"] = self._sign(payload)
        return model.wrap(body)

    def _backfill(
        self,
        package_id: str,
        envelope: dict[str, Any],
        envelopes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """把迟到的先前事件插回缺口，重建连续日志与状态。"""
        seq = envelope["body"]["seq"]
        if any(e["body"]["seq"] == seq for e in envelopes):
            raise CustodyError(f"seq={seq} 已存在，不应走回填")
        envelopes = envelopes + [envelope]
        envelopes.sort(key=lambda e: e["body"]["seq"])

        # 从创世起重放，确认回填后形成连续、首尾相接的链。
        last_digest = crypto.GENESIS_DIGEST
        expected_seq = 1
        for item in envelopes:
            body = item["body"]
            if body["seq"] != expected_seq or body["prev_digest"] != last_digest:
                raise CustodyError(
                    f"回填后链仍不连续: seq={body['seq']} 期望 {expected_seq}"
                )
            last_digest = item["digest"]
            expected_seq += 1

        self.store.replace_log(package_id, envelopes)
        pkg = self._pkg_state(package_id)
        pkg["next_seq"] = expected_seq
        pkg["last_digest"] = last_digest
        self.store.save_state(self.state)
        return {
            "status": "BACKFILLED",
            "package_id": package_id,
            "seq": seq,
            "digest": envelope["digest"],
        }

    def _conflict_certificate(
        self,
        package_id: str,
        seq: int,
        committed: Mapping[str, Any],
        arrived: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "type": "CONFLICT_CERTIFICATE",
            "package_id": package_id,
            "seq": seq,
            "committed": {
                "digest": committed["digest"],
                "prev_digest": committed["body"]["prev_digest"],
                "approval_gen": committed["body"]["approval_gen"],
                "manifest": committed["body"]["manifest"],
                "event_type": committed["body"]["event_type"],
            },
            "arrived": {
                "digest": arrived["digest"],
                "prev_digest": arrived["body"]["prev_digest"],
                "approval_gen": arrived["body"]["approval_gen"],
                "manifest": arrived["body"]["manifest"],
                "event_type": arrived["body"]["event_type"],
            },
            "rule": "同编号(seq)异摘要：已承诺封签与到达封签不可同时成立",
        }

    # ---- 测试辅助：制造缺段 --------------------------------------------------

    def inject_gap(self, package_id: str) -> int:
        """测试辅助：跳过下一个序号制造缺段（只推进状态，不写该 seq 封签）。

        日志里没有该 seq 的记录 -> 验证器必须判 GAP（缺段），
        而不能判 CONFLICT（恶意替换）。
        """
        with self._lock:
            pkg = self._pkg_state(package_id)
            missing_seq = pkg["next_seq"]
            pkg["next_seq"] += 1
            # last_digest 保持不变；后续真实记录的 prev_digest 会因此对不上，
            # 验证器即在 missing_seq 处停住并报告缺段。
            self.store.save_state(self.state)
            return missing_seq
