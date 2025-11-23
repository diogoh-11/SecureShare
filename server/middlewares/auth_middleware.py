from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session as DBSession
from database import get_db
from models.models import Session as SessionModel, User
import time

def __helper_get_user(
    authorization: str = Header(...),
    db: DBSession = Depends(get_db)
) -> User:
    """
    Verify session token and return current authenticated user.
    Raises:
        HTTPException: 401 if token is invalid or expired
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header format. Expected: Bearer <token>"
        )
    token = authorization[7:]
    # get session
    session = db.query(SessionModel).filter(
        SessionModel.session_token == token
    ).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")
    # check if session is expired
    if int(time.time()) > session.expires_at:
        raise HTTPException(status_code=401, detail="Session expired")
    # get user
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def get_current_user(
    authorization: str|None = Header(None),
    db: DBSession = Depends(get_db)
) -> User|None:
    """
    Returns the authenticated used is authenticated
    """
    if not authorization:
        return None
    try:
        return __helper_get_user(authorization, db)
    except HTTPException:
        return None

def delete_session(session_token: str, db: DBSession) -> bool:
    """
    Delete a session token.
    Args:
        session_token: session to delete
        db: session
    Returns:
        bool: was deleted?
    """
    # query session
    session = db.query(SessionModel).filter(
        SessionModel.session_token == session_token
    ).first()
    if not session:
        return False
    db.delete(session)
    db.commit()
    return True

def delete_all_user_sessions(user_id: int, db: DBSession) -> int:
    """
    Delete all sessions for a user
    Args:
        user_id: The user to be deleted
        db: session
    Returns:
        int: delete count
    """
    count = db.query(SessionModel).filter(
        SessionModel.user_id == user_id
    ).delete()
    db.commit()
    return count

def cleanup_expired_sessions(db: DBSession) -> int:
    """
    Delete expired sessions from database.
    Args:
        db: session
    Returns:
        int: delete count
    """
    # Delete expired sessions
    count = db.query(SessionModel).filter(
        SessionModel.expires_at < int(time.time())
    ).delete()
    db.commit()
    return count
