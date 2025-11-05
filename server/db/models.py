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
    password_hash = Column(String(255), nullable=False)          # Argon2 / PBKDF2
    one_time_password = Column(String(64), nullable=True)        # NULL após ativação
    is_active = Column(Boolean, nullable=False, default=False)
    role = Column(
        String(20),
        nullable=False,
        default="USER",
        # USER, SECURITY_OFFICER, TRUSTED_OFFICER, AUDITOR, ADMINISTRATOR
    )
    created_at = Column(DateTime, server_default=func.now())
    activated_at = Column(DateTime, nullable=True)

    # ----------- Relações 1:1 / 1:N ----------
    public_key = relationship(
        "UserPublicKey", uselist=False, back_populates="user", cascade="all, delete-orphan"
    )
    vault = relationship(
        "UserVault", uselist=False, back_populates="user", cascade="all, delete-orphan"
    )
    clearances = relationship(
        "ClearanceToken", back_populates="user", cascade="all, delete-orphan"
    )
    revocations = relationship(
        "ClearanceRevocation", back_populates="token", cascade="all, delete-orphan"
    )
    transfers = relationship("Transfer", back_populates="uploader")
    audit_entries = relationship("AuditLog", back_populates="actor")
    verifications = relationship("AuditVerification", back_populates="auditor")

    # ----------- Métodos úteis ----------
    def is_admin(self) -> bool:
        return self.role == "ADMINISTRATOR"

    def is_security_officer(self) -> bool:
        return self.role == "SECURITY_OFFICER"

    def __repr__(self) -> str:
        return f"<User {self.username} [{self.role}]>"


# ----------------------------------------------------------------------
# 2. CHAVE PÚBLICA DO USUÁRIO
# ----------------------------------------------------------------------
class UserPublicKey(Base):
    __tablename__ = "user_public_keys"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    public_key = Column(Text, nullable=False)          # PEM ou base64
    uploaded_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="public_key")


# ----------------------------------------------------------------------
# 3. VAULT (chave privada criptografada com senha)
# ----------------------------------------------------------------------
class UserVault(Base):
    __tablename__ = "user_vaults"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    encrypted_blob = Column(Text, nullable=False)      # ciphertext
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="vault")


# ----------------------------------------------------------------------
# 4. DEPARTAMENTOS (categorias do MLS)
# ----------------------------------------------------------------------
class Department(Base):
    __tablename__ = "departments"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())

    # Usado em ClearanceToken e Transfer via JSON
    __table_args__ = (Index("ix_departments_name", "name"),)


# ----------------------------------------------------------------------
# 5. CLEARANCE TOKENS (emitidos pelo Security Officer)
# ----------------------------------------------------------------------
class ClearanceToken(Base):
    __tablename__ = "clearance_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    level = Column(
        String(20), nullable=False
    )  # UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET
    departments_json = Column(JSON, nullable=False)   # ["Finance","HR"]
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    issued_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False, index=True)
    signature = Column(Text, nullable=False)          # assinatura do SO

    user = relationship("User", foreign_keys=[user_id], back_populates="clearances")
    issuer = relationship("User", foreign_keys=[issued_by])

    # Revogação aponta para este token
    revocations = relationship(
        "ClearanceRevocation", back_populates="token", cascade="all, delete-orphan"
    )

    @validates("departments_json")
    def validate_departments(self, key, value):
        if not isinstance(value, list):
            raise ValueError("departments_json must be a list")
        return value


# ----------------------------------------------------------------------
# 6. REVOGAÇÃO DE CLEARANCE
# ----------------------------------------------------------------------
class ClearanceRevocation(Base):
    __tablename__ = "clearance_revocations"

    id = Column(Integer, primary_key=True)
    token_id = Column(Integer, ForeignKey("clearance_tokens.id"), nullable=False)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    revoked_at = Column(DateTime, server_default=func.now())
    signature = Column(Text, nullable=False)

    token = relationship("ClearanceToken", back_populates="revocations")
    revoker = relationship("User")


# ----------------------------------------------------------------------
# 7. TRANSFERÊNCIAS (arquivos criptografados)
# ----------------------------------------------------------------------
class Transfer(Base):
    __tablename__ = "transfers"

    id = Column(Integer, primary_key=True)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    classification_level = Column(String(20), nullable=False)
    departments_json = Column(JSON, nullable=False)   # [] = organização geral
    is_public = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())
    deleted_at = Column(DateTime, nullable=True)     # soft-delete
    metadata_json = Column(JSON, nullable=True)      # nome, tamanho, mime, ...

    uploader = relationship("User", back_populates="transfers")
    encrypted_keys = relationship(
        "EncryptedFileKey", back_populates="transfer", cascade="all, delete-orphan"
    )

    @validates("departments_json")
    def validate_depts(self, key, value):
        if not isinstance(value, list):
            raise ValueError("departments_json must be a list")
        return value


# ----------------------------------------------------------------------
# 8. CHAVES DE ARQUIVO CRIPTOGRAFADAS (por destinatário)
# ----------------------------------------------------------------------
class EncryptedFileKey(Base):
    __tablename__ = "encrypted_file_keys"

    id = Column(Integer, primary_key=True)
    transfer_id = Column(Integer, ForeignKey("transfers.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_key = Column(Text, nullable=False)     # FileKey cifrada com pubkey do recipient

    transfer = relationship("Transfer", back_populates="encrypted_keys")
    recipient = relationship("User")

    __table_args__ = (
        Index("ix_unique_key_per_user", "transfer_id", "recipient_id", unique=True),
    )


# ----------------------------------------------------------------------
# 9. LOG DE AUDITORIA – HASH CHAIN
# ----------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(64), nullable=False)          # USER_CREATED, FILE_UPLOADED, …
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    target_id = Column(Integer, nullable=True)              # id do objeto afetado
    details_json = Column(JSON, nullable=True)              # dados estruturados
    timestamp = Column(DateTime, server_default=func.now())
    prev_hash = Column(String(64), nullable=False, default="GENESIS")
    current_hash = Column(String(64), nullable=False)

    actor = relationship("User", back_populates="audit_entries")
    verifications = relationship(
        "AuditVerification", back_populates="log_entry", cascade="all, delete-orphan"
    )

    # ---------- Hook automático para hash-chain ----------
    @staticmethod
    def _calc_hash(prev: str, payload: dict, ts: datetime) -> str:
        data = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(f"{prev}{data}{ts.isoformat()}".encode()).hexdigest()

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type} #{self.id}>"


# Hook que roda **antes** de INSERT
@event.listens_for(AuditLog, "before_insert")
def _audit_before_insert(mapper, connection, target):
    # 1. Último hash
    last = connection.execute(
        text("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    ).fetchone()
    prev = last[0] if last else "GENESIS"

    # 2. Payload serializável
    payload = {
        "id": target.id,
        "event_type": target.event_type,
        "actor_id": target.actor_id,
        "target_id": target.target_id,
        "details": target.details_json or {},
    }

    target.prev_hash = prev
    target.current_hash = AuditLog._calc_hash(prev, payload, target.timestamp)


# ----------------------------------------------------------------------
# 10. VERIFICAÇÃO DO AUDITOR (Verification Object)
# ----------------------------------------------------------------------
class AuditVerification(Base):
    __tablename__ = "audit_verifications"

    id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey("audit_log.id"), nullable=False)
    auditor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    statement = Column(Text, nullable=False)               # "Log válido até aqui"
    timestamp = Column(DateTime, server_default=func.now())
    signature = Column(Text, nullable=False)               # assinatura do auditor

    log_entry = relationship("AuditLog", back_populates="verifications")
    auditor = relationship("User", back_populates="verifications")
