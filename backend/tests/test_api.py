"""
Unit tests for SentinelGrid API
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data
    assert "version" in data

def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        assert b"<!DOCTYPE html>" in response.content or b"html" in response.content.lower()
    else:
        data = response.json()
        assert data["status"] == "healthy"


def test_ingest_endpoint():
    """Test attack event ingestion"""
    event_data = {
        "service": "SSH",
        "source_ip": "192.168.1.100",
        "username": "admin",
        "password": "password123",
        "severity": "HIGH",
        "command": "ls -la"
    }
    
    response = client.post("/api/ingest", json=event_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert "id" in data

def test_login_valid_credentials():
    """Test login with valid credentials"""
    response = client.post("/auth/login", data={
        "username": "admin",
        "password": "admin123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    response = client.post("/auth/login", data={
        "username": "admin",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_protected_endpoint_without_token():
    """Test protected endpoint without authentication"""
    response = client.get("/api/events")
    assert response.status_code == 401

def test_protected_endpoint_with_token():
    """Test protected endpoint with valid token"""
    # First login
    login_response = client.post("/auth/login", data={
        "username": "admin",
        "password": "admin123"
    })
    token = login_response.json()["access_token"]
    
    # Then access protected endpoint
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/events", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_statistics_endpoint():
    """Test statistics endpoint"""
    # Login first
    login_response = client.post("/auth/login", data={
        "username": "admin",
        "password": "admin123"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/api/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "events_by_service" in data
    assert "events_by_severity" in data