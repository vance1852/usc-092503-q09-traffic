"""分配与工单操作向调用方暴露的稳定错误。"""
from __future__ import annotations


class Conflict(ValueError):
    """请求关键内容与已提交记录冲突（如数量变化），业务状态保持不变。"""
