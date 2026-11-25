# -*- coding: utf-8 -*-
"""磁盘存储层：合成物证文件、只追加日志、原子状态写、读访问计数。

目录布局（全部本地合成、离线）::

    root/
      state.json                       服务状态（批准代、每包序号/末摘要）
      packages/<package_id>/
          files/<相对路径...>          实际物证文件目录
          log.jsonl                    只追加的封签日志（每行一条外壳）
          conflicts/seq-<n>-<短摘要>.json   冲突证书

访问计数用于规模实验：:meth:`reset_metrics` 清零后，
:meth:`read_log` 每读一个包记一次（去重）、每读一条记录记一次，
从而回答“补一个包的先前事件时只访问了多少包、多少条记录”。
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import crypto


class FileStore:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.packages_root = os.path.join(self.root, "packages")
        self.state_path = os.path.join(self.root, "state.json")
        os.makedirs(self.packages_root, exist_ok=True)
        self._packages_accessed: set[str] = set()
        self._records_read = 0

    # ---- 路径 ----------------------------------------------------------------

    def package_dir(self, package_id: str) -> str:
        return os.path.join(self.packages_root, package_id)

    def files_dir(self, package_id: str) -> str:
        return os.path.join(self.package_dir(package_id), "files")

    def log_path(self, package_id: str) -> str:
        return os.path.join(self.package_dir(package_id), "log.jsonl")

    def conflict_dir(self, package_id: str) -> str:
        return os.path.join(self.package_dir(package_id), "conflicts")

    def ensure_package(self, package_id: str) -> None:
        os.makedirs(self.files_dir(package_id), exist_ok=True)
        os.makedirs(self.conflict_dir(package_id), exist_ok=True)

    def list_packages(self) -> list[str]:
        if not os.path.isdir(self.packages_root):
            return []
        return sorted(
            name
            for name in os.listdir(self.packages_root)
            if os.path.isdir(os.path.join(self.packages_root, name))
        )

    # ---- 物证文件与目录清单 --------------------------------------------------

    def write_file(self, package_id: str, rel_path: str, data: bytes) -> None:
        # 统一用 / 作为清单内分隔符，Windows 反斜杠不入摘要。
        rel_norm = rel_path.replace("\\", "/")
        target = os.path.join(self.files_dir(package_id), *rel_norm.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    def manifest_from_disk(self, package_id: str) -> dict[str, str]:
        """扫描实际文件目录，返回 {相对路径: sha256}，按路径排序。"""
        base = self.files_dir(package_id)
        manifest: dict[str, str] = {}
        if not os.path.isdir(base):
            return manifest
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, base).replace("\\", "/")
                with open(full, "rb") as fh:
                    manifest[rel] = crypto.sha256_hex(fh.read())
        return dict(sorted(manifest.items()))

    # ---- 只追加日志 ----------------------------------------------------------

    def append_log(self, package_id: str, envelope: dict[str, Any]) -> None:
        path = self.log_path(package_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        line = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def read_log(self, package_id: str) -> list[dict[str, Any]]:
        """读取一个包的全部封签；日志不存在视为空（缺段检测在验证器层）。"""
        self._packages_accessed.add(package_id)
        path = self.log_path(package_id)
        if not os.path.exists(path):
            return []
        envelopes: list[dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    envelopes.append(json.loads(line))
                    self._records_read += 1
        return envelopes

    def replace_log(self, package_id: str, envelopes: list[dict[str, Any]]) -> None:
        """整包重写日志（仅用于缺段回填：先移除占位居段再补真实旧事件）。

        临时文件 + os.replace 保证同目录原子替换。
        """
        path = self.log_path(package_id)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for envelope in envelopes:
                fh.write(
                    json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                )
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # ---- 冲突证书 ------------------------------------------------------------

    def write_conflict(self, package_id: str, certificate: dict[str, Any]) -> str:
        directory = self.conflict_dir(package_id)
        os.makedirs(directory, exist_ok=True)
        seq = certificate["seq"]
        short = crypto.digest_json(certificate)[:12]
        path = os.path.join(directory, f"seq-{seq}-{short}.json")
        self.atomic_write_json(path, certificate)
        return path

    def list_conflicts(self, package_id: str) -> list[str]:
        directory = self.conflict_dir(package_id)
        if not os.path.isdir(directory):
            return []
        return sorted(
            os.path.join(directory, name)
            for name in os.listdir(directory)
            if name.endswith(".json")
        )

    # ---- 服务状态（原子写）---------------------------------------------------

    def load_state(self) -> dict[str, Any]:
        if not os.path.exists(self.state_path):
            return {"generation": 0, "packages": {}}
        with open(self.state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def save_state(self, state: dict[str, Any]) -> None:
        self.atomic_write_json(self.state_path, state)

    def atomic_write_json(self, path: str, obj: Any) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # ---- 访问计数 ------------------------------------------------------------

    def reset_metrics(self) -> None:
        self._packages_accessed.clear()
        self._records_read = 0

    def metrics(self) -> dict[str, int]:
        return {
            "packages_accessed": len(self._packages_accessed),
            "records_read": self._records_read,
        }
