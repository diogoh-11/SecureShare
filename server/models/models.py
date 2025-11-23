from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, LargeBinary, Table
import time
from database import Base

user_department = Table(
    'user_department',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('department_id', Integer, ForeignKey('departments.id'), primary_key=True)
)

clearance_department = Table(
    'clearance_department',
    Base.metadata,
    Column('clearance_token_id', Integer, ForeignKey('clearance_tokens.id'), primary_key=True),
    Column('department_id', Integer, ForeignKey('departments.id'), primary_key=True)
)


class Organization(Base):
    __tablename__ = 'organizations'

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String, unique=True, nullable = False)


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    public_key = Column(LargeBinary, unique=True, nullable=True)
    private_key_blob = Column(LargeBinary, nullable=True)
    is_active = Column(Boolean, default=False)

class RecoveryTokens(Base):
    __tablename__ = 'recovery_tokens'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    hashed_value = Column(String, unique=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)


class WebAuthnCredential(Base):
    """cridentials for fido2"""
    #TODO: may need more indo idk
    __tablename__ = 'webauthn_credentials'

    id =            Column(Integer, primary_key=True, index=True)
    user_id =       Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    credential_id = Column(LargeBinary, unique=True, nullable=False, index=True)
    public_key =    Column(LargeBinary, nullable=False)
    sign_count =    Column(Integer, default=0, nullable=False)
    created_at =    Column(Integer, default=lambda: int(time.time()), nullable=False)


class WebAuthnChallenge(Base):
    """challenges for validation"""
    __tablename__ = 'webauthn_challenges'

    id =                Column(Integer, primary_key=True, index=True)
    username =          Column(String, nullable=False, index=True)
    challenge =         Column(LargeBinary, nullable=False)
    expires_at =        Column(Integer, nullable=False)
    challenge_type =    Column(String, nullable=False) # TOCHECK: better approach for this line
    is_used =           Column(Boolean, default=False, nullable=False)


class Session(Base):
    """Session management"""
    __tablename__ = 'sessions'

    id =            Column(Integer, primary_key=True, index=True)
    user_id =       Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_token = Column(String, unique=True, nullable=False, index=True)
    created_at =    Column(Integer, default=lambda: int(time.time()), nullable=False)
    expires_at =    Column(Integer, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    previousHash = Column(String, nullable=False)
    entryHash = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    action = Column(String, nullable=False)

    actor_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class AuditVerification(Base):
    __tablename__ = "audit_verification"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    verifiedUpToHash = Column(String, nullable=False)
    signature = Column(String, nullable=False)

    audit_log_entry_id = Column(Integer, ForeignKey("audit_log.id"), nullable=False)
    auditor_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class Department(Base):
    __tablename__ = 'departments'

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
    label = Column(String, unique=True, nullable=False)


class ClearanceLevel(Base):
    __tablename__ = 'clearance_levels'

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String, unique=True, nullable=False)


class Transfer(Base):
    __tablename__ = 'transfers'

    id = Column(Integer, primary_key=True, index=True)
    expiration_time = Column(DateTime)
    classification_level_id = Column(Integer, ForeignKey('clearance_levels.id'), nullable=False)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)


class TransferKey(Base):
    __tablename__ = 'transfer_keys'

    transfer_id = Column(Integer, ForeignKey('transfers.id'), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    encrypted_key = Column(LargeBinary, nullable=False)

class Role(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String, unique=True, nullable=False)


class RoleToken(Base):
    __tablename__ = 'role_tokens'

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(String, ForeignKey('roles.id') ,nullable=False)
    signature = Column(LargeBinary, nullable=False)
    expires_at = Column(DateTime)
    target_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    issuer_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)


class RoleRevocation(Base):
    __tablename__ = 'role_revocations'

    role_token_id = Column(Integer, ForeignKey('role_tokens.id'), primary_key=True)
    revoker_id = Column(Integer, ForeignKey('users.id'), nullable=False)


class ClearanceToken(Base):
    __tablename__ = 'clearance_tokens'

    id = Column(Integer, primary_key=True, index=True)
    expiration_time = Column(DateTime)
    is_organizational = Column(Boolean, default=False)
    issuer_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    clearance_level_id = Column(Integer, ForeignKey('clearance_levels.id'), nullable=False)
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=False)
