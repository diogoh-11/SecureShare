from enum import Enum


class RoleEnum(str, Enum):
    ADMINISTRATOR      = "Administrator"
    SECURITY_OFFICER   = "Security Officer"
    TRUSTED_OFFICER    = "Trusted Officer"
    STANDARD_USER      = "Standard User"
    AUDITOR            = "Auditor"


class ClearanceLevelEnum(str, Enum):
    TOP_SECRET      = "Top Secret"
    SECRET          = "Secret"
    CONFIDENTIAL    = "Confidential"
    UNCLASSIFIED    = "Unclassified"
