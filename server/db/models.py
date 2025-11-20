"""
SecureShare – SQLAlchemy models
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column, Integer, String, DateTime, JSON, Boolean,
    ForeignKey, Text, Index, event, func, text
)
from sqlalchemy.orm import declarative_base, relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

Base = declarative_base()


# ----------------------------------------------------------------------
# 1. USUÁRIOS
# ----------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    activation_code = Column(String(64), nullable=True)
    is_active = Column(Boolean, nullable=False, default=False)
    public_key = Column(Text, nullable=True)
    encrypted_vault = Column(Text, nullable=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relações
    role_tokens = relationship("RoleToken", foreign_keys="RoleToken.user_id", back_populates="user")
    clearance_tokens = relationship("ClearanceToken", foreign_keys="ClearanceToken.user_id", back_populates="user")
    transfers = relationship("Transfer", back_populates="uploader")
    audit_entries = relationship("AuditLogEntry", back_populates="actor")
    verifications = relationship("AuditVerification", back_populates="auditor")

    def __repr__(self) -> str:
        return f"<User {self.username}>"


# ----------------------------------------------------------------------
# 2. ROLE TOKENS
# ----------------------------------------------------------------------
class RoleToken(Base):
    __tablename__ = "role_tokens"

    id = Column(Integer, primary_key=True)
    role = Column(String(20), nullable=False)
    issued_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False, index=True)
    signature = Column(Text, nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    issuer_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", foreign_keys=[user_id], back_populates="role_tokens")
    issuer = relationship("User", foreign_keys=[issuer_id])
    revocations = relationship("RoleRevocation", back_populates="role_token", cascade="all, delete-orphan")


# ----------------------------------------------------------------------
# 3. ROLE REVOCATION
# ----------------------------------------------------------------------
class RoleRevocation(Base):
    __tablename__ = "role_revocations"

    id = Column(Integer, primary_key=True)
    revoked_at = Column(DateTime, server_default=func.now())
    signature = Column(Text, nullable=False)
    role_token_id = Column(Integer, ForeignKey("role_tokens.id"), nullable=False)
    revoker_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    role_token = relationship("RoleToken", back_populates="revocations")
    revoker = relationship("User")


# ----------------------------------------------------------------------
# 4. CLEARANCE TOKENS
# ----------------------------------------------------------------------
class ClearanceToken(Base):
    __tablename__ = "clearance_tokens"

    id = Column(Integer, primary_key=True)
    level = Column(String(20), nullable=False)
    departments = Column(JSON, nullable=False)
    issued_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False, index=True)
    signature = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    issuer_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", foreign_keys=[user_id], back_populates="clearance_tokens")
    issuer = relationship("User", foreign_keys=[issuer_id])

    @validates("departments")
    def validate_departments(self, key, value):
        if not isinstance(value, list):
            raise ValueError("departments must be a list")
        return value


# ----------------------------------------------------------------------
# 5. TRANSFERS
# ----------------------------------------------------------------------
class Transfer(Base):
    __tablename__ = "transfers"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    classification_level = Column(String(20), nullable=False)
    departments = Column(JSON, nullable=False)
    is_public = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    encrypted_blob_path = Column(String(512), nullable=True)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    uploader = relationship("User", back_populates="transfers")
    encrypted_keys = relationship("EncryptedFileKey", back_populates="transfer", cascade="all, delete-orphan")

    @validates("departments")
    def validate_departments(self, key, value):
        if not isinstance(value, list):
            raise ValueError("departments must be a list")
        return value


# ----------------------------------------------------------------------
# 6. ENCRYPTED FILE KEYS
# ----------------------------------------------------------------------
class EncryptedFileKey(Base):
    __tablename__ = "encrypted_file_keys"

    transfer_id = Column(Integer, ForeignKey("transfers.id"), primary_key=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    encrypted_symmetric_key = Column(Text, nullable=False)

    transfer = relationship("Transfer", back_populates="encrypted_keys")
    recipient = relationship("User")


# ----------------------------------------------------------------------
# 7. AUDIT LOG ENTRY
# ----------------------------------------------------------------------
class AuditLogEntry(Base):
    __tablename__ = "audit_log_entries"

    id = Column(Integer, primary_key=True)
    previous_hash = Column(String(64), nullable=False, default="GENESIS")
    entry_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime, server_default=func.now())
    action = Column(String(64), nullable=False)
    details = Column(JSON, nullable=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    actor = relationship("User", back_populates="audit_entries")
    verifications = relationship("AuditVerification", back_populates="log_entry", cascade="all, delete-orphan")

    @staticmethod
    def _calc_hash(prev: str, payload: dict, ts: datetime) -> str:
        data = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(f"{prev}{data}{ts.isoformat()}".encode()).hexdigest()

    def __repr__(self) -> str:
        return f"<AuditLogEntry {self.action} #{self.id}>"


# Hook que roda **antes** de INSERT
@event.listens_for(AuditLogEntry, "before_insert")
def _audit_before_insert(mapper, connection, target):
    last = connection.execute(
        text("SELECT entry_hash FROM audit_log_entries ORDER BY id DESC LIMIT 1")
    ).fetchone()
    prev = last[0] if last else "GENESIS"

    payload = {
        "id": target.id,
        "action": target.action,
        "actor_id": target.actor_id,
        "details": target.details or {},
    }

    target.previous_hash = prev
    target.entry_hash = AuditLogEntry._calc_hash(prev, payload, target.timestamp)


# ----------------------------------------------------------------------
# 8. AUDIT VERIFICATION
# ----------------------------------------------------------------------
class AuditVerification(Base):
    __tablename__ = "audit_verifications"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, server_default=func.now())
    verified_up_to_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)
    audit_log_entry_id = Column(Integer, ForeignKey("audit_log_entries.id"), nullable=False)
    auditor_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    log_entry = relationship("AuditLogEntry", back_populates="verifications")
    auditor = relationship("User", back_populates="verifications")
