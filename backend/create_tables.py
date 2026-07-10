#!/usr/bin/env python3
"""
Create database tables for SentinelGrid
Run this to initialize the database with all required tables
"""

import sys
import os

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.database import engine, Base
from app.models import *  # Import all models

def create_tables():
    """Create all database tables"""
    print("🗄️ Creating database tables...")
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        
        # List created tables
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        print(f"\n📋 Created tables ({len(tables)}):")
        for table in sorted(tables):
            print(f"   - {table}")
            
    except Exception as e:
        print(f"❌ Failed to create tables: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = create_tables()
    if success:
        print("\n🎉 Database initialization complete!")
        print("You can now start the SentinelGrid backend server.")
    else:
        print("\n💥 Database initialization failed!")
        sys.exit(1)