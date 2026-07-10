from typing import Dict, Any, List

class ExplanationEngine:
    def __init__(self):
        pass
        
    def generate_explanations(self, deviation_scores: Dict[str, float], context: Dict[str, Any]) -> List[str]:
        """
        Translates raw deviation scores into human-readable explanations.
        """
        reasons = []
        
        # Check login time
        login_time = context.get('login_time')
        normal_hours = context.get('normal_hours', [])
        if login_time and normal_hours:
            hour = str(login_time.hour)
            if hour not in normal_hours:
                reasons.append(f"login occurred at an unusual time ({login_time.strftime('%I:%M %p')})")
                
        # Check location
        location = context.get('location')
        typical_locations = context.get('typical_locations', [])
        if location and typical_locations and location not in typical_locations:
            reasons.append(f"first login from foreign location: {location}")
            
        # Feature deviations
        file_access_deviation = deviation_scores.get('file_access', 0)
        if file_access_deviation > 5:
            # We assume the deviation is an absolute count difference for this example
            reasons.append(f"abnormally high file access volume (+{int(file_access_deviation)} above average)")
            
        api_call_deviation = deviation_scores.get('api_calls', 0)
        if api_call_deviation > 10:
            reasons.append(f"unusual API call frequency (+{int(api_call_deviation)} above average)")
            
        if not reasons:
            reasons.append("abnormal behavior pattern detected by ML model")
            
        return reasons
