# -*- coding: utf-8 -*-
"""离线物证完整性检查 —— 纯标准库实现（Windows / Python 3.12）。

子模块：
    crypto   规范化编码、SHA-256 摘要、两位独立签核人各自的 HMAC
    model    保管事件记录、摘要链、记录自洽校验
    storage  只追加日志、原子写、读访问计数
    service  交接 / 撤销 / 恢复 / 代次轮换 / 冲突证书 / 缺段回填
    verifier 新的只读验证器：实际目录 vs 已承诺前缀 vs 最早可证冲突
"""

__all__ = ["crypto", "model", "storage", "service", "verifier"]
