from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from schemas.schemas import CreateTransferRequest

router = APIRouter(tags=["File Transfers"])


@router.get("/transfers")
async def list_transfers():
    """
    Lists existing transfers created by the user.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Fetch user's transfers from DB
    pass


@router.post("/transfers")
async def create_transfer(
    file: UploadFile = File(...),
    metadata: str = None  # JSON string of CreateTransferRequest
):
    """
    Uploads an encrypted file and its metadata.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Verify MLS constraints (user can write at this classification)
    # TODO: Save encrypted file to filesystem
    # TODO: Store metadata and encrypted keys in DB
    # TODO: Return transfer_id
    pass


@router.get("/transfers/{transfer_id}")
async def get_transfer(transfer_id: int):
    """
    Retrieves transfer metadata and the user's encrypted File Key.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Verify MLS access (user can read this classification)
    # TODO: Fetch transfer metadata
    # TODO: Return metadata and user's encrypted key
    pass


@router.delete("/transfers/{transfer_id}")
async def delete_transfer(transfer_id: int):
    """
    Delete transfer metadata and data.
    Authorization: Authenticated User (owner)
    """
    # TODO: Verify authentication
    # TODO: Verify user is owner
    # TODO: Delete file from filesystem
    # TODO: Delete metadata from DB
    pass


@router.get("/download/{transfer_id}")
async def download_transfer(transfer_id: int):
    """
    Downloads the raw encrypted file blob.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Verify MLS access
    # TODO: Return encrypted file blob
    pass
