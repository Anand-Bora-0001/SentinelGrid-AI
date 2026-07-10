"""
SentinelGrid WebSocket Manager
Handles real-time WebSocket connections, authentication, and message broadcasting
"""
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from fastapi import WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
import jwt
from .config import settings

logger = logging.getLogger(__name__)

class ConnectionResult(BaseModel):
    """Result of WebSocket connection attempt"""
    success: bool
    user_id: Optional[str] = None
    error_message: Optional[str] = None

class WebSocketMessage(BaseModel):
    """WebSocket message structure"""
    type: str
    data: Dict[str, Any]
    timestamp: str
    sequence: int

class WebSocketAuth:
    """WebSocket authentication handler"""
    
    @staticmethod
    def authenticate_token(token: str) -> Optional[Dict]:
        """Authenticate JWT token for WebSocket connection"""
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm]
            )
            
            username = payload.get("sub")
            role = payload.get("role")
            
            if not username:
                return None
            
            return {
                "username": username,
                "role": role,
                "authenticated": True
            }
            
        except jwt.ExpiredSignatureError:
            logger.warning("WebSocket authentication failed: Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"WebSocket authentication failed: Invalid token - {e}")
            return None
        except Exception as e:
            logger.error(f"WebSocket authentication error: {e}")
            return None

class MessageFilter:
    """Filters messages based on client subscriptions"""
    
    def __init__(self):
        self.subscription_filters = {
            'new_attack': self._filter_security_events,
            'stats_update': self._filter_stats_updates,
            'system_alert': self._filter_system_alerts,
            'heartbeat': self._filter_heartbeat
        }
    
    def should_send_message(self, message: WebSocketMessage, subscriptions: Set[str]) -> bool:
        """Determine if message should be sent to client based on subscriptions"""
        if not subscriptions:
            return True  # Send all messages if no specific subscriptions
        
        message_type = message.type
        if message_type in subscriptions:
            # Apply specific filter if available
            filter_func = self.subscription_filters.get(message_type)
            if filter_func:
                return filter_func(message)
            return True
        
        return False
    
    def _filter_security_events(self, message: WebSocketMessage) -> bool:
        """Filter attack event messages"""
        # Could filter based on severity, service, etc.
        return True
    
    def _filter_stats_updates(self, message: WebSocketMessage) -> bool:
        """Filter statistics update messages"""
        return True
    
    def _filter_system_alerts(self, message: WebSocketMessage) -> bool:
        """Filter system alert messages"""
        return True
    
    def _filter_heartbeat(self, message: WebSocketMessage) -> bool:
        """Filter heartbeat messages"""
        return True

class WebSocketConnection:
    """Represents a single WebSocket connection"""
    
    def __init__(self, websocket: WebSocket, user: Dict, connection_id: str):
        self.websocket = websocket
        self.user = user
        self.connection_id = connection_id
        self.connected_at = datetime.now()
        self.last_heartbeat = datetime.now()
        self.subscriptions: Set[str] = set()
        self.is_active = True
        self.message_count = 0
    
    async def send_message(self, message: WebSocketMessage):
        """Send message to this connection"""
        try:
            await self.websocket.send_text(message.json())
            self.message_count += 1
            logger.debug(f"Message sent to {self.connection_id}: {message.type}")
        except Exception as e:
            logger.error(f"Failed to send message to {self.connection_id}: {e}")
            self.is_active = False
    
    def update_heartbeat(self):
        """Update last heartbeat timestamp"""
        self.last_heartbeat = datetime.now()
    
    def add_subscription(self, event_type: str):
        """Add event type subscription"""
        self.subscriptions.add(event_type)
        logger.info(f"Connection {self.connection_id} subscribed to {event_type}")
    
    def remove_subscription(self, event_type: str):
        """Remove event type subscription"""
        self.subscriptions.discard(event_type)
        logger.info(f"Connection {self.connection_id} unsubscribed from {event_type}")
    
    def get_info(self) -> Dict:
        """Get connection information"""
        return {
            'connection_id': self.connection_id,
            'user': self.user.get('username'),
            'role': self.user.get('role'),
            'connected_at': self.connected_at.isoformat(),
            'last_heartbeat': self.last_heartbeat.isoformat(),
            'subscriptions': list(self.subscriptions),
            'message_count': self.message_count,
            'is_active': self.is_active
        }

class WebSocketManager:
    """Manages WebSocket connections and message broadcasting"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.auth = WebSocketAuth()
        self.message_filter = MessageFilter()
        self.sequence_counter = 0
        self.heartbeat_interval = 30  # seconds
        self.connection_timeout = 300  # 5 minutes
        
        # Start background tasks
        asyncio.create_task(self._heartbeat_task())
        asyncio.create_task(self._cleanup_task())
    
    async def connect(self, websocket: WebSocket, token: str) -> ConnectionResult:
        """Handle new WebSocket connection with authentication"""
        try:
            # Authenticate the connection
            user = self.auth.authenticate_token(token)
            if not user:
                await websocket.close(code=4001, reason="Authentication failed")
                return ConnectionResult(
                    success=False,
                    error_message="Authentication failed"
                )
            
            # Accept the WebSocket connection
            await websocket.accept()
            
            # Create connection object
            connection_id = f"{user['username']}_{datetime.now().timestamp()}"
            connection = WebSocketConnection(websocket, user, connection_id)
            
            # Store connection
            self.connections[connection_id] = connection
            
            logger.info(f"WebSocket connection established: {connection_id} ({user['username']})")
            
            # Send welcome message
            welcome_message = WebSocketMessage(
                type="connection_established",
                data={
                    "connection_id": connection_id,
                    "user": user['username'],
                    "server_time": datetime.now().isoformat()
                },
                timestamp=datetime.now().isoformat(),
                sequence=self._get_next_sequence()
            )
            
            await connection.send_message(welcome_message)
            
            return ConnectionResult(
                success=True,
                user_id=user['username']
            )
            
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return ConnectionResult(
                success=False,
                error_message=str(e)
            )
    
    async def disconnect(self, websocket: WebSocket) -> None:
        """Handle WebSocket disconnection"""
        # Find and remove connection
        connection_to_remove = None
        for connection_id, connection in self.connections.items():
            if connection.websocket == websocket:
                connection_to_remove = connection_id
                break
        
        if connection_to_remove:
            connection = self.connections.pop(connection_to_remove)
            connection.is_active = False
            logger.info(f"WebSocket connection closed: {connection_to_remove}")
        else:
            logger.warning("WebSocket disconnection: Connection not found")
    
    async def handle_message(self, websocket: WebSocket, message: str):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            # Find connection
            connection = self._find_connection_by_websocket(websocket)
            if not connection:
                logger.warning("Received message from unknown connection")
                return
            
            # Handle different message types
            if message_type == 'heartbeat':
                connection.update_heartbeat()
                await self._send_heartbeat_response(connection)
            
            elif message_type == 'subscribe':
                event_types = data.get('event_types', [])
                for event_type in event_types:
                    connection.add_subscription(event_type)
            
            elif message_type == 'unsubscribe':
                event_types = data.get('event_types', [])
                for event_type in event_types:
                    connection.remove_subscription(event_type)
            
            else:
                logger.warning(f"Unknown message type: {message_type}")
        
        except json.JSONDecodeError:
            logger.error("Invalid JSON in WebSocket message")
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
    
    async def broadcast_event(self, event_type: str, data: Dict[str, Any]):
        """Broadcast event to all connected clients"""
        if not self.connections:
            return
        
        message = WebSocketMessage(
            type=event_type,
            data=data,
            timestamp=datetime.now().isoformat(),
            sequence=self._get_next_sequence()
        )
        
        # Send to all connections that should receive this message
        tasks = []
        for connection in self.connections.values():
            if connection.is_active and self.message_filter.should_send_message(message, connection.subscriptions):
                tasks.append(connection.send_message(message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info(f"Broadcasted {event_type} to {len(tasks)} connections")
    
    async def send_to_user(self, username: str, event_type: str, data: Dict[str, Any]):
        """Send message to specific user"""
        message = WebSocketMessage(
            type=event_type,
            data=data,
            timestamp=datetime.now().isoformat(),
            sequence=self._get_next_sequence()
        )
        
        # Find connections for the user
        user_connections = [
            conn for conn in self.connections.values()
            if conn.user.get('username') == username and conn.is_active
        ]
        
        if user_connections:
            tasks = [conn.send_message(message) for conn in user_connections]
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info(f"Sent {event_type} to user {username} ({len(user_connections)} connections)")
    
    def get_connection_stats(self) -> Dict:
        """Get WebSocket connection statistics"""
        active_connections = sum(1 for conn in self.connections.values() if conn.is_active)
        total_messages = sum(conn.message_count for conn in self.connections.values())
        
        user_counts = {}
        for conn in self.connections.values():
            if conn.is_active:
                username = conn.user.get('username', 'unknown')
                user_counts[username] = user_counts.get(username, 0) + 1
        
        return {
            'total_connections': len(self.connections),
            'active_connections': active_connections,
            'total_messages_sent': total_messages,
            'users_connected': len(user_counts),
            'connections_per_user': user_counts,
            'sequence_counter': self.sequence_counter
        }
    
    def get_active_connections(self) -> List[Dict]:
        """Get list of active connections"""
        return [
            conn.get_info() for conn in self.connections.values()
            if conn.is_active
        ]
    
    def _find_connection_by_websocket(self, websocket: WebSocket) -> Optional[WebSocketConnection]:
        """Find connection by WebSocket object"""
        for connection in self.connections.values():
            if connection.websocket == websocket:
                return connection
        return None
    
    def _get_next_sequence(self) -> int:
        """Get next sequence number for messages"""
        self.sequence_counter += 1
        return self.sequence_counter
    
    async def _send_heartbeat_response(self, connection: WebSocketConnection):
        """Send heartbeat response to connection"""
        heartbeat_message = WebSocketMessage(
            type="heartbeat_response",
            data={"server_time": datetime.now().isoformat()},
            timestamp=datetime.now().isoformat(),
            sequence=self._get_next_sequence()
        )
        await connection.send_message(heartbeat_message)
    
    async def _heartbeat_task(self):
        """Background task to send periodic heartbeats"""
        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                if self.connections:
                    heartbeat_data = {
                        "server_time": datetime.now().isoformat(),
                        "active_connections": len([c for c in self.connections.values() if c.is_active])
                    }
                    await self.broadcast_event("heartbeat", heartbeat_data)
                
            except Exception as e:
                logger.error(f"Heartbeat task error: {e}")
    
    async def _cleanup_task(self):
        """Background task to clean up inactive connections"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute
                
                current_time = datetime.now()
                connections_to_remove = []
                
                for connection_id, connection in self.connections.items():
                    # Check if connection is inactive or timed out
                    time_since_heartbeat = (current_time - connection.last_heartbeat).total_seconds()
                    
                    if not connection.is_active or time_since_heartbeat > self.connection_timeout:
                        connections_to_remove.append(connection_id)
                
                # Remove inactive connections
                for connection_id in connections_to_remove:
                    connection = self.connections.pop(connection_id, None)
                    if connection:
                        try:
                            await connection.websocket.close()
                        except:
                            pass  # Connection might already be closed
                        logger.info(f"Cleaned up inactive connection: {connection_id}")
                
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

# Global WebSocket manager instance
websocket_manager = WebSocketManager()
