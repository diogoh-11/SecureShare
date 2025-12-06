from pydantic import BaseModel
from typing import List, Optional


# Authentication Schemas
class LoginRequest(BaseModel):
    username: str
    password: str


class ActivateRequest(BaseModel):
    username: str
    one_time_password: str
    password: str
    public_key: str


# Department Schemas
class CreateDepartmentRequest(BaseModel):
    name: str


class DepartmentResponse(BaseModel):
    id: int
    name: str


# User Schemas
class CreateUserRequest(BaseModel):
    username: str


class UpdateRoleRequest(BaseModel):
    role: str
    signed_role_token: str
    expires_at: Optional[str] = None


class ClearanceRequest(BaseModel):
    clearance_level: str
    departments: List[str]
    expires_at: str
    signed_token: str
    is_organizational: bool = False


class UpdateUserInfoRequest(BaseModel):
    password: Optional[str] = None


class VaultRequest(BaseModel):
    encrypted_private_key_blob: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: Optional[str] = None
    activated: bool


class PublicKeyResponse(BaseModel):
    user_id: int
    public_key: str


# Transfer Schemas
class CreateTransferRequest(BaseModel):
    classification_level: str
    departments: List[str]
    encrypted_file_keys: List[dict]  # {user_id: encrypted_key}
    expiration_days: int
    original_filenames: List[str]


class TransferResponse(BaseModel):
    transfer_id: int
    classification_level: str
    departments: List[str]
    created_at: str
    expires_at: str
    original_filenames: List[str]


# Organization Schemas
class CreateOrganizationRequest(BaseModel):
    org_name: str
    admin_username: str


class OrganizationCreationResponse(BaseModel):
    success:bool
    message: str
    username: str
    activation_code: str
    org_name: str


class OrganizationResponse(BaseModel):
    id: int
    admin_id: int
    name: str
