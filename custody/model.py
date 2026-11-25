# -*- coding: utf-8 -*-
"""保管事件记录模型与摘要链。

一条记录的外壳（envelope）::

    {
      "body":   <记录本体，见下>,
      "digest": SHA256(canonical(body))
    }

记录本体字段
------------
package_id   物证包编号
seq          包内单调序号（从 1 开始）
event_type   HANDOFF（交接）/ REVOKE（撤销）
prev_digest  前一条记录的摘要；首条固定为 crypto.GENESIS_DIGEST
manifest     实际文件目录清单 {相对路径: sha256}，来自真实磁盘目录
approval_gen 批准代（generation），撤销轮换后旧代封签即失效
nonce        合成随机值，防止同内容碰撞出同摘要
signoffs     {"A": hmac, "B": hmac}，两位独立签核人

验证器只信任重算结果，不信任日志里现成的 digest / signoffs。
"""

from __future__ import annotations

import hmac
from typing import Any, Mapping

from . import crypto

HANDOFF = "HANDOFF"
REVOKE = "REVOKE"
EVENT_TYPES = (HANDOFF, REVOKE)


def build_body(
    *,
    package_id: str,
    seq: int,
    event_type: str,
    prev_digest: str,
    manifest: Mapping[str, str],
    approval_gen: int,
    nonce: str,
    signoffs: Mapping[str, str],
) -> dict[str, Any]:
    """组装记录本体（manifest / signoffs 做拷贝，杜绝外部别名修改）。"""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"未知事件类型: {event_type!r}")
    if seq < 1:
        raise ValueError("seq 必须从 1 开始")
    if not isinstance(approval_gen, int) or approval_gen < 0:
        raise ValueError("approval_gen 必须是非负整数")
    return {
        "package_id": package_id,
        "seq": seq,
        "event_type": event_type,
        "prev_digest": prev_digest,
        "manifest": dict(manifest),
        "approval_gen": approval_gen,
        "nonce": nonce,
        "signoffs": dict(signoffs),
    }


def signing_payload(body: Mapping[str, Any]) -> str:
    """签核载荷：去掉 signoffs 字段后的本体摘要。

    签核本身也是本体字段，若直接对含签核的本体签名会形成自指。
    因此约定两位签核人都对“无签核本体”的摘要负责；记录外壳的
    digest 仍覆盖完整本体（含签核），两层各司其职。
    """
    base = {k: v for k, v in body.items() if k != "signoffs"}
    return crypto.digest_json(base)


def wrap(body: Mapping[str, Any]) -> dict[str, Any]:
    """本体 -> 带摘要外壳。"""
    return {"body": dict(body), "digest": crypto.digest_json(body)}


def envelope_digest(envelope: Mapping[str, Any]) -> str:
    return str(envelope["digest"])


def check_envelope_integrity(envelope: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """重算本体摘要并与外壳声明比对；同时做结构字段检查。"""
    problems: list[str] = []
    if not isinstance(envelope, Mapping) or "body" not in envelope or "digest" not in envelope:
        return False, ["记录外壳缺少 body/digest"]
    body = envelope["body"]
    if not isinstance(body, Mapping):
        return False, ["body 不是映射"]

    declared = envelope.get("digest")
    actual = crypto.digest_json(body)
    if not hmac.compare_digest(actual, str(declared)):
        problems.append(f"摘要不符: 声明 {declared} 实算 {actual}")

    required = {
        "package_id", "seq", "event_type", "prev_digest",
        "manifest", "approval_gen", "nonce", "signoffs",
    }
    missing = required - set(body)
    if missing:
        problems.append(f"本体缺字段: {sorted(missing)}")
    if body.get("event_type") not in EVENT_TYPES:
        problems.append(f"event_type 非法: {body.get('event_type')!r}")
    if not isinstance(body.get("seq"), int) or body.get("seq", 0) < 1:
        problems.append("seq 非法")
    if not isinstance(body.get("manifest"), Mapping):
        problems.append("manifest 不是映射")
    if not isinstance(body.get("signoffs"), Mapping):
        problems.append("signoffs 不是映射")
    return not problems, problems


def check_signoffs(
    envelope: Mapping[str, Any], keys: Mapping[str, bytes]
) -> tuple[bool, list[str]]:
    """对“无签核本体”的摘要校验两位独立签核。"""
    payload = signing_payload(envelope["body"])
    return crypto.verify_two_signoffs(payload, envelope["body"]["signoffs"], keys)
