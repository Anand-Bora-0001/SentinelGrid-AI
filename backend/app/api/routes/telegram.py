"""
Telegram configuration, validation, and test routes.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging

from ..deps import get_current_user, get_db
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/telegram", tags=["Telegram"])


@router.get("/first-login-check")
async def check_first_login(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Check if this is the user's first login and if Telegram needs configuration"""
    try:
        from ...telegram_config import telegram_config_manager
        is_first_login = telegram_config_manager.is_first_login(current_user["username"], db)
        telegram_config = telegram_config_manager.get_telegram_config(current_user["username"], db)
        return {
            "is_first_login": is_first_login,
            "telegram_configured": bool(telegram_config),
            "needs_telegram_setup": is_first_login and not telegram_config,
            "user_role": current_user.get("role"),
            "username": current_user["username"]
        }
    except Exception as e:
        return {"is_first_login": False, "telegram_configured": False, "needs_telegram_setup": False, "error": str(e)}


@router.post("/configure")
async def configure_telegram(request: dict, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Configure Telegram bot token and chat ID"""
    try:
        from ...telegram_config import telegram_config_manager
        bot_token = request.get("bot_token", "").strip()
        chat_id = request.get("chat_id", "").strip()
        if not bot_token or not chat_id:
            raise HTTPException(status_code=400, detail="Bot token and chat ID are required")
        result = telegram_config_manager.save_telegram_config(username=current_user["username"], bot_token=bot_token, chat_id=chat_id, db=db)
        if result["success"]:
            return {"status": "success", "message": result["message"], "bot_username": result.get("bot_username")}
        else:
            raise HTTPException(status_code=400, detail=result.get("details", result["error"]))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Configuration failed: {str(e)}")


@router.post("/validate")
async def validate_telegram_credentials(request: dict, current_user: dict = Depends(get_current_user)):
    """Validate Telegram bot token and chat ID without saving"""
    try:
        from ...telegram_config import telegram_config_manager
        bot_token = request.get("bot_token", "").strip()
        chat_id = request.get("chat_id", "").strip()
        if not bot_token or not chat_id:
            raise HTTPException(status_code=400, detail="Bot token and chat ID are required")
        result = telegram_config_manager.validate_telegram_credentials(bot_token, chat_id)
        if result["valid"]:
            return {"status": "success", "message": result["message"], "bot_username": result.get("bot_username")}
        else:
            return {"status": "error", "error": result["error"], "details": result["details"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.post("/test")
async def test_telegram(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Send a test message using saved Telegram configuration"""
    try:
        from ...telegram_config import telegram_config_manager
        result = telegram_config_manager.send_test_message(current_user["username"], db)
        if result["success"]:
            return {"status": "success", "message": result["message"]}
        else:
            raise HTTPException(status_code=400, detail=result.get("details", result["error"]))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


@router.get("/config")
async def get_telegram_configuration(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current Telegram configuration status"""
    try:
        from ...telegram_config import telegram_config_manager
        config = telegram_config_manager.get_telegram_config(current_user["username"], db)
        if config:
            return {
                "configured": True, "enabled": config["enabled"],
                "chat_id": config["chat_id"][:10] + "..." if len(config["chat_id"]) > 10 else config["chat_id"],
                "bot_token_set": bool(config["bot_token"])
            }
        return {"configured": False, "enabled": False, "chat_id": None, "bot_token_set": False}
    except Exception as e:
        return {"configured": False, "enabled": False, "error": str(e)}


@router.post("/skip-setup")
async def skip_telegram_setup(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Skip Telegram setup (mark as no longer first login)"""
    try:
        from ...models import User
        user = db.query(User).filter(User.username == current_user["username"]).first()
        if user:
            user.is_first_login = False
            db.commit()
            return {"status": "success", "message": "Telegram setup skipped."}
        raise HTTPException(status_code=404, detail="User not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
