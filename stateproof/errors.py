"""错误类型。CLI 据此输出 error.type 并以退出码 2 退出。"""


class StateProofError(Exception):
    """所有 stateproof 受控错误的基类。"""

    type = "InputError"

    def __init__(self, message, *, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self):
        d = {"type": self.type, "message": self.message}
        if self.details:
            d["details"] = self.details
        return d


class InputError(StateProofError):
    """参数非法（缺少必需参数、样本数非正整数等）。"""

    type = "InputError"


class RootUnavailable(StateProofError):
    """root 不可用（不存在、不是目录、无法遍历/读取）。"""

    type = "RootUnavailable"


class ProofFormatError(StateProofError):
    """证明文件缺失、不可解析或结构/字段不合法。"""

    type = "ProofFormatError"


class ChallengeRangeError(StateProofError):
    """挑战越界：无文件可抽样，或请求样本数超过可抽样分块总数。"""

    type = "ChallengeRangeError"


class ResponseFormatError(StateProofError):
    """挑战响应（离线凭证）缺失、不可解析，或结构/字段/证据/重建结果不合法。"""

    type = "ResponseFormatError"


class StateConflict(StateProofError):
    """状态冲突：状态文件不属于该 proof_id，或结构非法无法继续。"""

    type = "StateConflict"
