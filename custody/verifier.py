# -*- coding: utf-8 -*-
"""只读验证器（新组件）：从实际文件目录出发，独立重算所有承诺。

验证器不持有写权限、不信任 state.json，也不信任日志里现成的摘要与签核，
只做三件事：

1. 从创世起逐条重放封签，确定**已承诺前缀**（最长的连续有效链段）；
2. 找出**最早可证冲突**——同序号异摘要、摘要/签核伪造、前一摘要绑定
   不符、批准代回退；缺段（GAP）与恶意替换（CONFLICT）严格区分；
3. 扫描**实际文件目录**，与前缀末端记录绑定的目录清单逐文件比对。

结论类型
--------
OK                 链完整且目录一致
GAP                缺段：序号不连续，证据不足，绝不判恶意替换
CONFLICT           同编号异摘要/绑定不符等可证冲突
INVALID_SIGNATURE  封签摘要或双签核重算失败
STALE_GENERATION   批准代回退（迟到的旧代封签进入了序列）
DIR_DRIFT          链本身有效，但实际目录与承诺清单不一致
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from . import crypto, model
from .storage import FileStore

# 链层面的结论
CHAIN_OK = "OK"
CHAIN_GAP = "GAP"
CHAIN_CONFLICT = "CONFLICT"
CHAIN_INVALID = "INVALID_SIGNATURE"
CHAIN_STALE = "STALE_GENERATION"

# 目录层面的结论
DIR_MATCH = "MATCH"
DIR_DRIFT = "DRIFT"
DIR_NO_PROMISE = "NO_PROMISE"


@dataclass
class Issue:
    """最早可证问题（缺段或冲突）。"""
    issue_type: str
    seq: int
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class PackageReport:
    package_id: str
    chain_status: str
    directory_status: str
    committed_seq_lo: int          # 已承诺前缀覆盖的序号区间（无承诺时 lo > hi）
    committed_seq_hi: int
    last_committed_digest: str
    issue: Issue | None
    dir_diff: dict[str, Any]
    records_in_log: int
    records_in_prefix: int
    unexamined_after_issue: int

    @property
    def overall(self) -> str:
        if self.chain_status != CHAIN_OK:
            return self.chain_status
        if self.directory_status == DIR_DRIFT:
            return "DIR_DRIFT"
        return "OK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "overall": self.overall,
            "chain_status": self.chain_status,
            "directory_status": self.directory_status,
            "committed_prefix": [self.committed_seq_lo, self.committed_seq_hi],
            "last_committed_digest": self.last_committed_digest,
            "issue": None
            if self.issue is None
            else {
                "issue_type": self.issue.issue_type,
                "seq": self.issue.seq,
                "reason": self.issue.reason,
                "evidence": self.issue.evidence,
            },
            "dir_diff": self.dir_diff,
            "records_in_log": self.records_in_log,
            "records_in_prefix": self.records_in_prefix,
            "unexamined_after_issue": self.unexamined_after_issue,
        }


class ReadOnlyVerifier:
    """只读：构造后只调用 store 的读取方法，绝不写任何文件。"""

    def __init__(self, store: FileStore, keys: Mapping[str, bytes]):
        self.store = store
        self.keys = dict(keys)

    # ---- 单包验证 ------------------------------------------------------------

    def verify_package(self, package_id: str) -> PackageReport:
        envelopes = self.store.read_log(package_id)
        prefix, issue, index_at_issue = self._replay_chain(envelopes)

        if prefix:
            last = prefix[-1]
            hi = last["body"]["seq"]
            last_digest = last["digest"]
            directory_status, dir_diff = self._check_directory(package_id, last)
        else:
            hi = 0
            last_digest = crypto.GENESIS_DIGEST
            directory_status, dir_diff = DIR_NO_PROMISE, {}

        chain_status = CHAIN_OK if issue is None else issue.issue_type
        return PackageReport(
            package_id=package_id,
            chain_status=chain_status,
            directory_status=directory_status,
            committed_seq_lo=1 if prefix else 0,
            committed_seq_hi=hi,
            last_committed_digest=last_digest,
            issue=issue,
            dir_diff=dir_diff,
            records_in_log=len(envelopes),
            records_in_prefix=len(prefix),
            unexamined_after_issue=max(0, len(envelopes) - index_at_issue),
        )

    def verify_all(self) -> dict[str, PackageReport]:
        return {
            package_id: self.verify_package(package_id)
            for package_id in self.store.list_packages()
        }

    # ---- 链重放：承诺前缀 + 最早可证冲突/缺段 -------------------------------

    def _replay_chain(
        self, envelopes: list[Mapping[str, Any]]
    ) -> tuple[list[Mapping[str, Any]], Issue | None, int]:
        prefix: list[Mapping[str, Any]] = []
        last_digest = crypto.GENESIS_DIGEST
        expected_seq = 1
        last_gen = 0
        seen: dict[int, str] = {}

        for index, envelope in enumerate(envelopes):
            at = index + 1  # 问题定位用：日志中的第几条（1 起）

            ok, problems = model.check_envelope_integrity(envelope)
            if not ok:
                return prefix, Issue(
                    CHAIN_INVALID, at, "封签外壳摘要重算不符（记录被篡改或伪造）",
                    {"problems": problems},
                ), index

            body = envelope["body"]
            sig_ok, sig_problems = model.check_signoffs(envelope, self.keys)
            if not sig_ok:
                return prefix, Issue(
                    CHAIN_INVALID, body.get("seq", at),
                    "两位独立签核校验失败", {"problems": sig_problems},
                ), index

            seq = body["seq"]

            # 同序号二次出现：同摘要=幂等重复；异摘要=最早可证冲突。
            if seq in seen:
                if seen[seq] == envelope["digest"]:
                    continue  # 幂等重复，不破坏前缀
                return prefix, Issue(
                    CHAIN_CONFLICT, seq,
                    "同编号异摘要：同一序号出现两个互斥封签",
                    {
                        "committed_digest": seen[seq],
                        "arrived_digest": envelope["digest"],
                    },
                ), index

            # 序号跳跃 => 缺段。这是证据不足，不是恶意替换。
            if seq > expected_seq:
                return prefix, Issue(
                    CHAIN_GAP, expected_seq,
                    f"缺段：缺少 seq={expected_seq}..{seq - 1} 的封签，"
                    "现有证据无法判定为恶意替换",
                    {"expected_seq": expected_seq, "arrived_seq": seq},
                ), index

            # 序号倒退且非重复，无法归入任何合法位置。
            if seq < expected_seq:
                return prefix, Issue(
                    CHAIN_CONFLICT, seq,
                    "序号倒退且与已承诺封签摘要不同",
                    {"expected_seq": expected_seq},
                ), index

            # 同序号位置上前一摘要绑定不符 => 两条竞争历史。
            if body["prev_digest"] != last_digest:
                return prefix, Issue(
                    CHAIN_CONFLICT, seq,
                    "前一摘要绑定不符：该序号封签未链接到已承诺前缀末端",
                    {
                        "expected_prev_digest": last_digest,
                        "declared_prev_digest": body["prev_digest"],
                    },
                ), index

            # 批准代只允许单调不减；回退即迟到的旧代封签。
            if body["approval_gen"] < last_gen:
                return prefix, Issue(
                    CHAIN_STALE, seq,
                    "批准代回退：迟到的旧代封签",
                    {
                        "previous_approval_gen": last_gen,
                        "record_approval_gen": body["approval_gen"],
                    },
                ), index

            # 通过全部检查，纳入已承诺前缀。
            prefix.append(envelope)
            seen[seq] = envelope["digest"]
            last_digest = envelope["digest"]
            last_gen = body["approval_gen"]
            expected_seq = seq + 1

        return prefix, None, len(envelopes)

    # ---- 实际目录 vs 前缀末端承诺清单 ---------------------------------------

    def _check_directory(
        self, package_id: str, last_envelope: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        promised = last_envelope["body"]["manifest"]
        actual = self.store.manifest_from_disk(package_id)

        missing = sorted(set(promised) - set(actual))
        extra = sorted(set(actual) - set(promised))
        changed = sorted(
            rel
            for rel in set(promised) & set(actual)
            if promised[rel] != actual[rel]
        )
        diff = {
            "missing_on_disk": missing,
            "extra_on_disk": extra,
            "hash_mismatch": {
                rel: {"promised": promised[rel], "actual": actual[rel]}
                for rel in changed
            },
            "promised_file_count": len(promised),
            "actual_file_count": len(actual),
        }
        if missing or extra or changed:
            return DIR_DRIFT, diff
        return DIR_MATCH, diff

    # ---- 文本化 --------------------------------------------------------------

    @staticmethod
    def format_report(report: PackageReport) -> str:
        data = report.to_dict()
        lines = [
            f"包 {report.package_id}: 总结论={report.overall}",
            f"  链状态={report.chain_status} 目录状态={report.directory_status}",
            f"  已承诺前缀=seq {report.committed_seq_lo}..{report.committed_seq_hi}"
            f"（{report.records_in_prefix} 条），日志共 {report.records_in_log} 条",
            f"  前缀末端摘要={report.last_committed_digest[:16]}…",
        ]
        if report.issue is not None:
            lines.append(
                f"  最早可证问题: [{report.issue.issue_type}] seq={report.issue.seq}"
                f" {report.issue.reason}"
            )
            for key, value in report.issue.evidence.items():
                lines.append(f"      {key}={value}")
            lines.append(
                f"  问题之后未纳入判定的记录数={report.unexamined_after_issue}"
            )
        if report.directory_status == DIR_DRIFT:
            lines.append(f"  目录差异={report.dir_diff}")
        return "\n".join(lines)
