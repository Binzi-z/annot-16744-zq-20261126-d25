# -*- coding: utf-8 -*-
"""规范化编码、摘要与两位独立签核（仅标准库 hashlib / hmac）。

设计要点
--------
* 所有结构化数据先经过 :func:`canonical` 做确定性 JSON 编码（键排序、
  无空白、保留 UTF-8），再参与摘要，避免不同字典插入顺序导致摘要漂移。
* 记录摘要 = SHA-256(规范化后的记录本体)。
* 两位签核人 ``A`` / ``B`` 持有各自独立的 HMAC 密钥，对同一份记录摘要
  分别签名；任一枚举错或用同一把钥匙都无法通过
  :func:`verify_two_signoffs`。两把钥匙由合成数据派生，离线可用。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

#: 创世前一摘要：链上第一条记录固定绑定它。
GENESIS_DIGEST = "GENESIS"

#: 两位独立签核人标识。
SIGNERS = ("A", "B")


def canonical(obj: Any) -> bytes:
    """把嵌套结构编码成确定性字节串。"""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_json(obj: Any) -> str:
    """对任意可 JSON 化结构取 SHA-256 十六进制摘要。"""
    return sha256_hex(canonical(obj))


def hmac_hex(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def signer_keys(root_secret: str) -> dict[str, bytes]:
    """从一个合成根秘密派生两把互不相同的签核密钥。"""
    root = root_secret.encode("utf-8")
    return {
        "A": hashlib.sha256(b"custody-signer-A|" + root).digest(),
        "B": hashlib.sha256(b"custody-signer-B|" + root).digest(),
    }


def sign_digest(record_digest: str, signer: str, key: bytes) -> str:
    """某位签核人对记录摘要做 HMAC-SHA256。"""
    if signer not in SIGNERS:
        raise ValueError(f"未知签核人: {signer!r}")
    return hmac_hex(key, f"{signer}|{record_digest}".encode("utf-8"))


def verify_signoff(record_digest: str, signer: str, mac: str, key: bytes) -> bool:
    """常数时间比较，校验单个签核。"""
    if signer not in SIGNERS or not isinstance(mac, str):
        return False
    expected = sign_digest(record_digest, signer, key)
    return hmac.compare_digest(expected, mac)


def verify_two_signoffs(
    record_digest: str, signoffs: Mapping[str, str], keys: Mapping[str, bytes]
) -> tuple[bool, list[str]]:
    """校验两位独立签核人都用各自的钥匙签了同一份摘要。

    返回 ``(是否通过, 问题列表)``；问题列表为空即完全通过。
    """
    problems: list[str] = []
    if not isinstance(signoffs, Mapping):
        return False, ["签核字段不是映射"]
    for signer in SIGNERS:
        mac = signoffs.get(signer)
        if mac is None:
            problems.append(f"缺少签核人 {signer}")
        elif not verify_signoff(record_digest, signer, mac, keys[signer]):
            problems.append(f"签核人 {signer} 的签名无效")
    extra = set(signoffs) - set(SIGNERS)
    if extra:
        problems.append(f"存在多余签核人: {sorted(extra)}")
    return not problems, problems
