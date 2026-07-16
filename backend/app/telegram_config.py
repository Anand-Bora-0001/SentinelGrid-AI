"""
Telegram Configuration Management for SentinelGrid
Handles first-time setup and persistent storage of Telegram settings
"""
import logging
import requests
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException
from .models import User, NotificationConfig
from .database import get_db

logger = logging.getLogger(__name__)

class TelegramConfigManager:
    """Manages Telegram configuration for users and organizations"""
    
    @staticmethod
    def validate_telegram_credentials(bot_token: str, chat_id: str) -> Dict[str, Any]:
        """
        Validate Telegram bot token and chat ID by sending a test message
        
        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
            
        Returns:
            Dict with validation results
        """
        try:
            # Test the bot token by getting bot info
            bot_info_url = f"https://api.telegram.org/bot{bot_token}/getMe"
            bot_response = requests.get(bot_info_url, timeout=10)
            
            if not bot_response.ok:
                return {
                    "valid": False,
                    "error": "Invalid bot token",
                    "details": "Bot token is not valid or bot is not accessible"
                }
            
            bot_data = bot_response.json()
            if not bot_data.get("ok"):
                return {
                    "valid": False,
                    "error": "Bot token error",
                    "details": bot_data.get("description", "Unknown error")
                }
            
            bot_info = bot_data.get("result", {})
            bot_username = bot_info.get("username", "Unknown")
            
            # Test sending a message to the chat
            test_message = f" SentinelGrid Configuration Test\n\n Bot connected successfully!\n Bot: @{bot_username}\n Chat ID: {chat_id}\n\nYour Telegram alerts are now configured."
            
            send_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            send_payload = {
                'chat_id': chat_id,
                'text': test_message,
                'parse_mode': 'Markdown'
            }
            
            send_response = requests.post(send_url, json=send_payload, timeout=10)
            
            if not send_response.ok:
                error_data = send_response.json()
                error_description = error_data.get("description", "Unknown error")
                
                # Common error messages
                if "chat not found" in error_description.lower():
                    return {
                        "valid": False,
                        "error": "Chat ID not found",
                        "details": "The chat ID is invalid or the bot hasn't been added to the chat. Please start a conversation with the bot first."
                    }
                elif "forbidden" in error_description.lower():
                    return {
                        "valid": False,
                        "error": "Bot access forbidden",
                        "details": "The bot doesn't have permission to send messages to this chat. Please start a conversation with the bot."
                    }
                else:
                    return {
                        "valid": False,
                        "error": "Message send failed",
                        "details": error_description
                    }
            
            return {
                "valid": True,
                "bot_username": bot_username,
                "bot_name": bot_info.get("first_name", "Unknown"),
                "message": "Telegram configuration validated successfully!"
            }
            
        except requests.exceptions.Timeout:
            return {
                "valid": False,
                "error": "Connection timeout",
                "details": "Failed to connect to Telegram API. Please check your internet connection."
            }
        except requests.exceptions.RequestException as e:
            return {
                "valid": False,
                "error": "Network error",
                "details": f"Failed to connect to Telegram API: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Telegram validation error: {e}")
            return {
                "valid": False,
                "error": "Validation error",
                "details": f"An unexpected error occurred: {str(e)}"
            }
    
    @staticmethod
    def save_telegram_config(
        username: str, 
        bot_token: str, 
        chat_id: str, 
        db: Session
    ) -> Dict[str, Any]:
        """
        Save Telegram configuration for a user and their organization
        
        Args:
            username: Username of the user
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
            db: Database session
            
        Returns:
            Dict with save results
        """
        try:
            # Find the user
            user = db.query(User).filter(User.username == username).first()
            if not user:
                return {
                    "success": False,
                    "error": "User not found"
                }
            
            # Validate credentials first
            validation_result = TelegramConfigManager.validate_telegram_credentials(bot_token, chat_id)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"],
                    "details": validation_result["details"]
                }
            
            # Find or create notification config for the organization
            notification_config = db.query(NotificationConfig).filter(
                NotificationConfig.organization_id == user.organization_id
            ).first()
            
            if not notification_config:
                notification_config = NotificationConfig(
                    organization_id=user.organization_id,
                    telegram_enabled=True,
                    telegram_bot_token=bot_token,
                    telegram_chat_id=chat_id
                )
                db.add(notification_config)
            else:
                notification_config.telegram_enabled = True
                notification_config.telegram_bot_token = bot_token
                notification_config.telegram_chat_id = chat_id
            
            # Mark user as having configured Telegram and no longer first login
            user.telegram_configured = True
            user.is_first_login = False
            
            db.commit()
            
            logger.info(f" Telegram configured for user {username} and organization {user.organization.name}")
            
            return {
                "success": True,
                "message": "Telegram configuration saved successfully!",
                "bot_username": validation_result.get("bot_username"),
                "organization": user.organization.name
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save Telegram config: {e}")
            return {
                "success": False,
                "error": "Database error",
                "details": f"Failed to save configuration: {str(e)}"
            }
    
    @staticmethod
    def get_telegram_config(username: str, db: Session) -> Optional[Dict[str, Any]]:
        """
        Get Telegram configuration for a user's organization
        
        Args:
            username: Username of the user
            db: Database session
            
        Returns:
            Dict with Telegram config or None
        """
        try:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                return None
            
            notification_config = db.query(NotificationConfig).filter(
                NotificationConfig.organization_id == user.organization_id
            ).first()
            
            if not notification_config or not notification_config.telegram_enabled:
                return None
            
            return {
                "enabled": notification_config.telegram_enabled,
                "bot_token": notification_config.telegram_bot_token,
                "chat_id": notification_config.telegram_chat_id,
                "configured": user.telegram_configured
            }
            
        except Exception as e:
            logger.error(f"Failed to get Telegram config: {e}")
            return None
    
    @staticmethod
    def is_first_login(username: str, db: Session) -> bool:
        """
        Check if this is the user's first login
        
        Args:
            username: Username to check
            db: Database session
            
        Returns:
            True if first login, False otherwise
        """
        try:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                return False
            
            return user.is_first_login
            
        except Exception as e:
            logger.error(f"Failed to check first login status: {e}")
            return False
    
    @staticmethod
    def send_test_message(username: str, db: Session) -> Dict[str, Any]:
        """
        Send a test message using saved Telegram configuration
        
        Args:
            username: Username of the user
            db: Database session
            
        Returns:
            Dict with test results
        """
        try:
            config = TelegramConfigManager.get_telegram_config(username, db)
            if not config:
                return {
                    "success": False,
                    "error": "Telegram not configured"
                }
            
            test_message = f"""
 <b>SentinelGrid Test Message</b>

 <b>Status:</b> Configuration working perfectly!
 <b>User:</b> {username}
 <b>System:</b> All monitoring systems operational
 <b>Alerts:</b> Ready to send notifications
⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Your Telegram integration is working correctly.
            """
            
            url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
            payload = {
                'chat_id': config['chat_id'],
                'text': test_message.strip(),
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.ok:
                return {
                    "success": True,
                    "message": "Test message sent successfully!"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to send test message",
                    "details": response.text
                }
                
        except Exception as e:
            logger.error(f"Failed to send test message: {e}")
            return {
                "success": False,
                "error": "Test failed",
                "details": str(e)
            }

# Global instance
telegram_config_manager = TelegramConfigManager()
