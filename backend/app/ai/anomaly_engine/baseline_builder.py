import json
import numpy as np
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import SecurityTelemetry, BehaviorProfile

class BaselineBuilder:
    def __init__(self, db: Session):
        self.db = db

    def build_user_baseline(self, organization_id: int, username: str, days_history: int = 30):
        """Builds a behavior profile for a specific user based on historical telemetry."""
        # This is a simplified baseline builder. In production, this would use pandas and
        # aggregate large amounts of data.
        
        telemetry = self.db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == organization_id,
            SecurityTelemetry.user_identity == username
        ).all()
        
        if not telemetry:
            # Bootstrap a default baseline for new entities
            normal_hours = {"9": 1, "10": 1, "11": 1, "12": 1, "13": 1, "14": 1, "15": 1, "16": 1, "17": 1}
            typical_locations = ["India", "US"]
            avg_file_access = 1.0
            avg_api_calls = 5.0
            feature_vector = {
                "avg_file_access": avg_file_access,
                "avg_api_calls": avg_api_calls,
                "total_events": 0
            }
        else:
            # Extract features
            hours = [t.timestamp.hour for t in telemetry if t.timestamp]
            locations = [t.location.get('country') for t in telemetry if t.location and isinstance(t.location, dict)]
            
            # Calculate normal hours distribution (e.g., login times)
            hour_counts = {h: hours.count(h) for h in set(hours)}
            normal_hours = {str(k): v for k, v in hour_counts.items()}
            
            # Calculate typical locations
            location_counts = {loc: locations.count(loc) for loc in set(locations) if loc}
            typical_locations = list(location_counts.keys())
            
            # Averages (dummy calculation for demonstration)
            avg_file_access = sum(1 for t in telemetry if t.action == 'file_access') / max(1, days_history)
            avg_api_calls = sum(1 for t in telemetry if t.event_type == 'api_call') / max(1, days_history)
            
            # Construct feature vector for ML
            feature_vector = {
                "avg_file_access": avg_file_access,
                "avg_api_calls": avg_api_calls,
                "total_events": len(telemetry)
            }
        
        # Upsert BehaviorProfile
        profile = self.db.query(BehaviorProfile).filter(
            BehaviorProfile.organization_id == organization_id,
            BehaviorProfile.entity_type == 'user',
            BehaviorProfile.entity_id == username
        ).first()
        
        if not profile:
            profile = BehaviorProfile(
                organization_id=organization_id,
                entity_type='user',
                entity_id=username
            )
            self.db.add(profile)
            
        profile.normal_hours = normal_hours
        profile.typical_locations = typical_locations
        profile.avg_file_access = avg_file_access
        profile.avg_api_calls = avg_api_calls
        profile.feature_vector = feature_vector
        
        self.db.commit()
        self.db.refresh(profile)
        return profile
