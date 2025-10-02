from enum import Enum, auto

class AuthResult(Enum):
    SUCCESS = auto()
    INVALID_PASSWORD = auto()
    CONDITIONAL_ACCESS = auto()
    CONDITIONAL_ACCESS_DUO = auto()
    MFA_ENABLED = auto()
    PASSWORD_EXPIRED = auto()
    USER_NOT_FOUND = auto()
    TENANT_NOT_FOUND = auto()
    APPLICATION_NOT_FOUND = auto()
    EXTERNAL_AUTH = auto()
    ACCOUNT_LOCKED = auto()
    ACCOUNT_DISABLED = auto()
    OTHER_FAILURE = auto()
