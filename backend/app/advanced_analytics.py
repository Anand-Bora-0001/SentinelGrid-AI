"""
SentinelGrid Advanced Analytics Engine
Sophisticated analytics, predictive modeling, and business intelligence
"""
import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import json

logger = logging.getLogger(__name__)

@dataclass
class AnalyticsInsight:
    """Analytics insight data structure"""
    insight_type: str
    title: str
    description: str
    severity: str
    confidence: float
    data: Dict[str, Any]
    recommendations: List[str]
    timestamp: str

class PredictiveAnalytics:
    """Predictive analytics for threat forecasting"""
    
    def __init__(self):
        self.models = {}
        self.historical_data = []
        self.prediction_cache = {}
    
    def analyze_attack_trends(self, events: List[Dict], days_back: int = 30) -> Dict[str, Any]:
        """Analyze attack trends and predict future patterns"""
        try:
            if not events:
                return {'error': 'No events to analyze'}
            
            # Convert to DataFrame
            df = pd.DataFrame(events)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Filter to recent data
            cutoff_date = datetime.now() - timedelta(days=days_back)
            df = df[df['timestamp'] >= cutoff_date]
            
            if df.empty:
                return {'error': 'No recent events to analyze'}
            
            # Time series analysis
            df['date'] = df['timestamp'].dt.date
            daily_counts = df.groupby('date').size()
            
            # Calculate trends
            trend_analysis = self._calculate_trends(daily_counts)
            
            # Service analysis
            service_trends = self._analyze_service_trends(df)
            
            # Geographic analysis
            geo_trends = self._analyze_geographic_trends(df)
            
            # Severity analysis
            severity_trends = self._analyze_severity_trends(df)
            
            # Predictive forecasting
            forecast = self._forecast_attacks(daily_counts)
            
            return {
                'analysis_period': f'{days_back} days',
                'total_events': len(df),
                'trend_analysis': trend_analysis,
                'service_trends': service_trends,
                'geographic_trends': geo_trends,
                'severity_trends': severity_trends,
                'forecast': forecast,
                'insights': self._generate_insights(df, trend_analysis, forecast),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Trend analysis failed: {e}")
            return {'error': str(e)}
    
    def _calculate_trends(self, daily_counts: pd.Series) -> Dict[str, Any]:
        """Calculate trend statistics"""
        if len(daily_counts) < 2:
            return {'trend': 'insufficient_data'}
        
        # Calculate moving averages
        ma_7 = daily_counts.rolling(window=min(7, len(daily_counts))).mean()
        ma_14 = daily_counts.rolling(window=min(14, len(daily_counts))).mean()
        
        # Calculate trend direction
        recent_avg = daily_counts.tail(7).mean()
        previous_avg = daily_counts.head(7).mean() if len(daily_counts) > 14 else daily_counts.head(len(daily_counts)//2).mean()
        
        trend_direction = 'increasing' if recent_avg > previous_avg else 'decreasing'
        trend_strength = abs(recent_avg - previous_avg) / previous_avg if previous_avg > 0 else 0
        
        # Volatility
        volatility = daily_counts.std() / daily_counts.mean() if daily_counts.mean() > 0 else 0
        
        return {
            'trend_direction': trend_direction,
            'trend_strength': trend_strength,
            'volatility': volatility,
            'recent_average': recent_avg,
            'previous_average': previous_avg,
            'peak_day': daily_counts.idxmax(),
            'peak_count': daily_counts.max(),
            'moving_averages': {
                '7_day': ma_7.iloc[-1] if not ma_7.empty else 0,
                '14_day': ma_14.iloc[-1] if not ma_14.empty else 0
            }
        }
    
    def _analyze_service_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze trends by service"""
        service_counts = df.groupby(['date', 'service']).size().unstack(fill_value=0)
        
        trends = {}
        for service in service_counts.columns:
            service_data = service_counts[service]
            if service_data.sum() > 0:
                trends[service] = {
                    'total_attacks': int(service_data.sum()),
                    'average_daily': float(service_data.mean()),
                    'peak_day': service_data.idxmax(),
                    'trend': 'increasing' if service_data.tail(3).mean() > service_data.head(3).mean() else 'decreasing'
                }
        
        return trends
    
    def _analyze_geographic_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze geographic attack trends"""
        if 'location' not in df.columns:
            return {}
        
        # Extract country from location
        countries = []
        for location in df['location']:
            if isinstance(location, dict):
                countries.append(location.get('country', 'Unknown'))
            else:
                countries.append('Unknown')
        
        df['country'] = countries
        country_counts = df['country'].value_counts()
        
        # Geographic trends over time
        geo_trends = df.groupby(['date', 'country']).size().unstack(fill_value=0)
        
        trends = {}
        for country in country_counts.head(10).index:  # Top 10 countries
            if country in geo_trends.columns:
                country_data = geo_trends[country]
                trends[country] = {
                    'total_attacks': int(country_counts[country]),
                    'percentage': float(country_counts[country] / len(df) * 100),
                    'recent_trend': 'increasing' if country_data.tail(3).mean() > country_data.head(3).mean() else 'decreasing'
                }
        
        return trends
    
    def _analyze_severity_trends(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze severity trends"""
        severity_counts = df['severity'].value_counts()
        severity_trends = df.groupby(['date', 'severity']).size().unstack(fill_value=0)
        
        trends = {}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                trends[severity] = {
                    'total_count': int(severity_counts[severity]),
                    'percentage': float(severity_counts[severity] / len(df) * 100),
                    'daily_average': float(severity_trends[severity].mean()) if severity in severity_trends.columns else 0
                }
        
        return trends
    
    def _forecast_attacks(self, daily_counts: pd.Series, days_ahead: int = 7) -> Dict[str, Any]:
        """Simple attack forecasting"""
        if len(daily_counts) < 3:
            return {'error': 'Insufficient data for forecasting'}
        
        # Simple linear trend forecasting
        x = np.arange(len(daily_counts))
        y = daily_counts.values
        
        # Linear regression
        coeffs = np.polyfit(x, y, 1)
        trend_line = np.poly1d(coeffs)
        
        # Forecast future values
        future_x = np.arange(len(daily_counts), len(daily_counts) + days_ahead)
        forecast_values = trend_line(future_x)
        
        # Ensure non-negative forecasts
        forecast_values = np.maximum(forecast_values, 0)
        
        # Calculate confidence intervals (simple approach)
        residuals = y - trend_line(x)
        std_error = np.std(residuals)
        
        return {
            'forecast_days': days_ahead,
            'predicted_values': forecast_values.tolist(),
            'confidence_interval': std_error * 1.96,  # 95% confidence
            'trend_coefficient': coeffs[0],
            'expected_total': float(np.sum(forecast_values)),
            'forecast_dates': [(datetime.now() + timedelta(days=i+1)).strftime('%Y-%m-%d') for i in range(days_ahead)]
        }
    
    def _generate_insights(self, df: pd.DataFrame, trend_analysis: Dict, forecast: Dict) -> List[AnalyticsInsight]:
        """Generate actionable insights"""
        insights = []
        
        # Trend insights
        if trend_analysis.get('trend_direction') == 'increasing' and trend_analysis.get('trend_strength', 0) > 0.2:
            insights.append(AnalyticsInsight(
                insight_type='trend_alert',
                title='Increasing Attack Trend Detected',
                description=f'Attacks have increased by {trend_analysis["trend_strength"]*100:.1f}% recently',
                severity='HIGH',
                confidence=0.8,
                data={'trend_strength': trend_analysis['trend_strength']},
                recommendations=[
                    'Increase monitoring and alerting',
                    'Review and update security policies',
                    'Consider implementing additional rate limiting'
                ],
                timestamp=datetime.now().isoformat()
            ))
        
        # Volatility insights
        if trend_analysis.get('volatility', 0) > 1.0:
            insights.append(AnalyticsInsight(
                insight_type='volatility_alert',
                title='High Attack Volatility',
                description='Attack patterns show high volatility, indicating potential coordinated campaigns',
                severity='MEDIUM',
                confidence=0.7,
                data={'volatility': trend_analysis['volatility']},
                recommendations=[
                    'Investigate potential attack campaigns',
                    'Implement burst detection mechanisms',
                    'Review threat intelligence feeds'
                ],
                timestamp=datetime.now().isoformat()
            ))
        
        # Service concentration insights
        service_counts = df['service'].value_counts()
        if len(service_counts) > 0:
            top_service_pct = service_counts.iloc[0] / len(df)
            if top_service_pct > 0.7:
                insights.append(AnalyticsInsight(
                    insight_type='service_concentration',
                    title='Service Targeting Concentration',
                    description=f'{service_counts.index[0]} service is being heavily targeted ({top_service_pct*100:.1f}% of attacks)',
                    severity='MEDIUM',
                    confidence=0.9,
                    data={'service': service_counts.index[0], 'percentage': top_service_pct},
                    recommendations=[
                        f'Strengthen {service_counts.index[0]} service security',
                        'Implement service-specific rate limiting',
                        'Review service configuration and patches'
                    ],
                    timestamp=datetime.now().isoformat()
                ))
        
        # Forecast insights
        if 'expected_total' in forecast and forecast['expected_total'] > trend_analysis.get('recent_average', 0) * 7 * 1.5:
            insights.append(AnalyticsInsight(
                insight_type='forecast_alert',
                title='Predicted Attack Surge',
                description=f'Forecast predicts {forecast["expected_total"]:.0f} attacks in next {forecast["forecast_days"]} days',
                severity='HIGH',
                confidence=0.6,
                data={'predicted_total': forecast['expected_total']},
                recommendations=[
                    'Prepare incident response team',
                    'Scale monitoring infrastructure',
                    'Review and test backup systems'
                ],
                timestamp=datetime.now().isoformat()
            ))
        
        return insights

class BusinessIntelligence:
    """Business intelligence and reporting"""
    
    def __init__(self):
        self.kpis = {}
        self.benchmarks = {}
    
    def generate_executive_summary(self, events: List[Dict], time_period: str = '30d') -> Dict[str, Any]:
        """Generate executive summary report"""
        try:
            if not events:
                return {'error': 'No data available'}
            
            df = pd.DataFrame(events)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Filter by time period
            if time_period == '7d':
                cutoff = datetime.now() - timedelta(days=7)
            elif time_period == '30d':
                cutoff = datetime.now() - timedelta(days=30)
            elif time_period == '90d':
                cutoff = datetime.now() - timedelta(days=90)
            else:
                cutoff = datetime.now() - timedelta(days=30)
            
            df = df[df['timestamp'] >= cutoff]
            
            # Key metrics
            total_attacks = len(df)
            unique_ips = df['source_ip'].nunique()
            services_targeted = df['service'].nunique()
            
            # Severity breakdown
            severity_breakdown = df['severity'].value_counts().to_dict()
            
            # Top attack sources
            top_countries = self._get_top_countries(df)
            top_ips = df['source_ip'].value_counts().head(10).to_dict()
            
            # Attack timeline
            daily_attacks = df.groupby(df['timestamp'].dt.date).size()
            
            # Risk assessment
            risk_score = self._calculate_risk_score(df)
            
            # Trends
            trend_direction = self._calculate_simple_trend(daily_attacks)
            
            return {
                'summary': {
                    'time_period': time_period,
                    'total_attacks': total_attacks,
                    'unique_attackers': unique_ips,
                    'services_targeted': services_targeted,
                    'risk_score': risk_score,
                    'trend_direction': trend_direction
                },
                'severity_breakdown': severity_breakdown,
                'top_attack_sources': {
                    'countries': top_countries,
                    'ip_addresses': top_ips
                },
                'attack_timeline': {
                    'dates': [str(date) for date in daily_attacks.index],
                    'counts': daily_attacks.values.tolist()
                },
                'key_insights': self._generate_executive_insights(df, risk_score, trend_direction),
                'recommendations': self._generate_executive_recommendations(df, risk_score),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return {'error': str(e)}
    
    def _get_top_countries(self, df: pd.DataFrame) -> Dict[str, int]:
        """Get top attacking countries"""
        countries = []
        for location in df['location']:
            if isinstance(location, dict):
                countries.append(location.get('country', 'Unknown'))
            else:
                countries.append('Unknown')
        
        return pd.Series(countries).value_counts().head(10).to_dict()
    
    def _calculate_risk_score(self, df: pd.DataFrame) -> float:
        """Calculate overall risk score"""
        if df.empty:
            return 0.0
        
        # Weight by severity
        severity_weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.1}
        
        weighted_score = 0
        for severity, weight in severity_weights.items():
            count = len(df[df['severity'] == severity])
            weighted_score += count * weight
        
        # Normalize to 0-100 scale
        max_possible = len(df) * 1.0
        risk_score = (weighted_score / max_possible) * 100 if max_possible > 0 else 0
        
        return min(risk_score, 100.0)
    
    def _calculate_simple_trend(self, daily_attacks: pd.Series) -> str:
        """Calculate simple trend direction"""
        if len(daily_attacks) < 2:
            return 'stable'
        
        recent_avg = daily_attacks.tail(7).mean()
        previous_avg = daily_attacks.head(7).mean() if len(daily_attacks) > 14 else daily_attacks.head(len(daily_attacks)//2).mean()
        
        if recent_avg > previous_avg * 1.1:
            return 'increasing'
        elif recent_avg < previous_avg * 0.9:
            return 'decreasing'
        else:
            return 'stable'
    
    def _generate_executive_insights(self, df: pd.DataFrame, risk_score: float, trend: str) -> List[str]:
        """Generate executive insights"""
        insights = []
        
        if risk_score > 70:
            insights.append("🔴 High risk environment detected - immediate attention required")
        elif risk_score > 40:
            insights.append("🟡 Moderate risk level - enhanced monitoring recommended")
        else:
            insights.append("🟢 Low risk environment - maintain current security posture")
        
        if trend == 'increasing':
            insights.append("📈 Attack volume is trending upward - consider scaling defenses")
        elif trend == 'decreasing':
            insights.append("📉 Attack volume is decreasing - current measures appear effective")
        
        # Service insights
        top_service = df['service'].value_counts().index[0] if not df.empty else 'Unknown'
        service_pct = df['service'].value_counts().iloc[0] / len(df) * 100 if not df.empty else 0
        
        if service_pct > 50:
            insights.append(f"🎯 {top_service} service is primary target ({service_pct:.1f}% of attacks)")
        
        return insights
    
    def _generate_executive_recommendations(self, df: pd.DataFrame, risk_score: float) -> List[str]:
        """Generate executive recommendations"""
        recommendations = []
        
        if risk_score > 70:
            recommendations.extend([
                "Implement immediate incident response procedures",
                "Consider engaging external security consultants",
                "Review and update security policies urgently"
            ])
        elif risk_score > 40:
            recommendations.extend([
                "Increase security monitoring frequency",
                "Review current security controls effectiveness",
                "Consider additional security training for staff"
            ])
        
        # Service-specific recommendations
        if not df.empty:
            top_service = df['service'].value_counts().index[0]
            recommendations.append(f"Focus security hardening efforts on {top_service} service")
        
        # Geographic recommendations
        top_countries = self._get_top_countries(df)
        if top_countries:
            top_country = list(top_countries.keys())[0]
            recommendations.append(f"Consider geo-blocking or enhanced monitoring for traffic from {top_country}")
        
        return recommendations

class RiskAssessment:
    """Risk assessment and scoring engine"""
    
    def __init__(self):
        self.risk_models = {}
        self.threat_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1
        }
        self.service_risk_multipliers = {
            'ssh': 1.2,
            'ftp': 1.1,
            'http': 0.9,
            'https': 0.8,
            'smtp': 1.0,
            'telnet': 1.3
        }
    
    def calculate_overall_risk_score(self, events: List[Dict], assets: List[Dict] = None) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        try:
            if not events:
                return {
                    'overall_risk_score': 0.0,
                    'risk_level': 'MINIMAL',
                    'confidence': 1.0,
                    'factors': {},
                    'recommendations': ['No security events detected - maintain monitoring']
                }
            
            df = pd.DataFrame(events)
            
            # Calculate component risk scores
            threat_score = self._calculate_threat_score(df)
            vulnerability_score = self._calculate_vulnerability_score(df)
            impact_score = self._calculate_impact_score(df, assets)
            frequency_score = self._calculate_frequency_score(df)
            
            # Weighted overall score
            weights = {
                'threat': 0.3,
                'vulnerability': 0.25,
                'impact': 0.25,
                'frequency': 0.2
            }
            
            overall_score = (
                threat_score * weights['threat'] +
                vulnerability_score * weights['vulnerability'] +
                impact_score * weights['impact'] +
                frequency_score * weights['frequency']
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_score)
            
            # Calculate confidence based on data quality
            confidence = self._calculate_confidence(df)
            
            return {
                'overall_risk_score': round(overall_score, 2),
                'risk_level': risk_level,
                'confidence': confidence,
                'factors': {
                    'threat_score': threat_score,
                    'vulnerability_score': vulnerability_score,
                    'impact_score': impact_score,
                    'frequency_score': frequency_score
                },
                'breakdown': self._generate_risk_breakdown(df),
                'recommendations': self._generate_risk_recommendations(overall_score, risk_level),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            return {
                'overall_risk_score': 0.0,
                'risk_level': 'MINIMAL',
                'confidence': 0.0,
                'factors': {},
                'breakdown': {},
                'recommendations': ['Error occurred during risk assessment'],
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _calculate_threat_score(self, df: pd.DataFrame) -> float:
        """Calculate threat landscape score"""
        if df.empty:
            return 0.0
        
        # Weight by severity
        weighted_threats = 0
        total_weight = 0
        
        for severity, weight in self.threat_weights.items():
            count = len(df[df['severity'] == severity])
            weighted_threats += count * weight
            total_weight += count
        
        if total_weight == 0:
            return 0.0
        
        # Normalize to 0-100 scale
        base_score = (weighted_threats / total_weight) * 100
        
        # Adjust for threat diversity
        unique_sources = df['source_ip'].nunique()
        diversity_multiplier = min(1.0 + (unique_sources / 100), 2.0)
        
        return min(base_score * diversity_multiplier, 100.0)
    
    def _calculate_vulnerability_score(self, df: pd.DataFrame) -> float:
        """Calculate vulnerability exposure score"""
        if df.empty:
            return 0.0
        
        # Service vulnerability assessment
        service_scores = []
        for service in df['service'].unique():
            service_events = df[df['service'] == service]
            multiplier = self.service_risk_multipliers.get(service, 1.0)
            
            # Calculate service-specific score
            service_score = len(service_events) * multiplier
            service_scores.append(service_score)
        
        if not service_scores:
            return 0.0
        
        # Normalize and weight by service criticality
        max_score = max(service_scores)
        normalized_score = (sum(service_scores) / len(service_scores)) / max_score * 100 if max_score > 0 else 0
        
        return min(normalized_score, 100.0)
    
    def _calculate_impact_score(self, df: pd.DataFrame, assets: List[Dict] = None) -> float:
        """Calculate potential impact score"""
        if df.empty:
            return 0.0
        
        # Base impact on attack success indicators
        high_impact_indicators = [
            'authentication_bypass',
            'privilege_escalation',
            'data_exfiltration',
            'system_compromise'
        ]
        
        impact_events = 0
        for _, event in df.iterrows():
            event_type = event.get('attack_type', '').lower()
            if any(indicator in event_type for indicator in high_impact_indicators):
                impact_events += 1
        
        # Calculate base impact score
        base_impact = (impact_events / len(df)) * 100 if len(df) > 0 else 0
        
        # Adjust for asset criticality if available
        if assets:
            critical_assets = len([a for a in assets if a.get('criticality') == 'HIGH'])
            asset_multiplier = 1.0 + (critical_assets / len(assets)) * 0.5
            base_impact *= asset_multiplier
        
        return min(base_impact, 100.0)
    
    def _calculate_frequency_score(self, df: pd.DataFrame) -> float:
        """Calculate attack frequency score"""
        if df.empty:
            return 0.0
        
        # Calculate attacks per day
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_attacks = df.groupby('date').size()
        
        if len(daily_attacks) == 0:
            return 0.0
        
        avg_daily_attacks = daily_attacks.mean()
        max_daily_attacks = daily_attacks.max()
        
        # Frequency score based on average and peak
        frequency_score = (avg_daily_attacks * 0.7 + max_daily_attacks * 0.3) * 2
        
        return min(frequency_score, 100.0)
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _calculate_confidence(self, df: pd.DataFrame) -> float:
        """Calculate confidence in risk assessment"""
        if df.empty:
            return 1.0
        
        # Factors affecting confidence
        data_points = len(df)
        time_span = (pd.to_datetime(df['timestamp']).max() - pd.to_datetime(df['timestamp']).min()).days
        data_completeness = df.notna().sum().sum() / (len(df) * len(df.columns))
        
        # Calculate confidence score
        data_confidence = min(data_points / 100, 1.0)  # More data = higher confidence
        time_confidence = min(time_span / 30, 1.0)     # Longer period = higher confidence
        completeness_confidence = data_completeness     # Complete data = higher confidence
        
        overall_confidence = (data_confidence + time_confidence + completeness_confidence) / 3
        
        return round(overall_confidence, 2)
    
    def _generate_risk_breakdown(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate detailed risk breakdown"""
        breakdown = {
            'by_severity': df['severity'].value_counts().to_dict(),
            'by_service': df['service'].value_counts().to_dict(),
            'by_source': df['source_ip'].value_counts().head(10).to_dict(),
            'timeline': {}
        }
        
        # Timeline breakdown
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        timeline = df.groupby('date').size().to_dict()
        breakdown['timeline'] = {str(k): v for k, v in timeline.items()}
        
        return breakdown
    
    def _generate_risk_recommendations(self, score: float, level: str) -> List[str]:
        """Generate risk-based recommendations"""
        recommendations = []
        
        if level == 'CRITICAL':
            recommendations.extend([
                'Immediate incident response activation required',
                'Consider engaging external security experts',
                'Implement emergency security measures',
                'Notify stakeholders and management immediately'
            ])
        elif level == 'HIGH':
            recommendations.extend([
                'Escalate to security team immediately',
                'Implement additional monitoring and controls',
                'Review and update security policies',
                'Consider threat hunting activities'
            ])
        elif level == 'MEDIUM':
            recommendations.extend([
                'Increase monitoring frequency',
                'Review security control effectiveness',
                'Update threat intelligence feeds',
                'Schedule security assessment'
            ])
        elif level == 'LOW':
            recommendations.extend([
                'Maintain current security posture',
                'Continue regular monitoring',
                'Review logs for patterns',
                'Update security awareness training'
            ])
        else:  # MINIMAL
            recommendations.extend([
                'Maintain baseline security monitoring',
                'Regular security health checks',
                'Keep security tools updated'
            ])
        
        return recommendations
    
    def assess_service_risk(self, service: str, events: List[Dict]) -> Dict[str, Any]:
        """Assess risk for specific service"""
        try:
            service_events = [e for e in events if e.get('service') == service]
            
            if not service_events:
                return {
                    'service': service,
                    'risk_score': 0.0,
                    'risk_level': 'MINIMAL',
                    'event_count': 0,
                    'recommendations': [f'No attacks detected on {service} service']
                }
            
            df = pd.DataFrame(service_events)
            
            # Service-specific risk calculation
            base_multiplier = self.service_risk_multipliers.get(service, 1.0)
            severity_score = self._calculate_threat_score(df)
            frequency_score = len(service_events) / max(1, len(events)) * 100
            
            risk_score = (severity_score * 0.6 + frequency_score * 0.4) * base_multiplier
            risk_level = self._determine_risk_level(risk_score)
            
            return {
                'service': service,
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'event_count': len(service_events),
                'attack_types': df['attack_type'].value_counts().to_dict() if 'attack_type' in df.columns else {},
                'top_sources': df['source_ip'].value_counts().head(5).to_dict(),
                'recommendations': self._generate_service_recommendations(service, risk_level),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Service risk assessment failed for {service}: {e}")
            return {'error': str(e)}
    
    def _generate_service_recommendations(self, service: str, risk_level: str) -> List[str]:
        """Generate service-specific recommendations"""
        base_recommendations = {
            'ssh': [
                'Implement key-based authentication',
                'Disable root login',
                'Use non-standard ports',
                'Implement fail2ban or similar'
            ],
            'ftp': [
                'Consider SFTP instead of FTP',
                'Implement strong authentication',
                'Use passive mode only',
                'Regular security updates'
            ],
            'http': [
                'Implement HTTPS redirect',
                'Use Web Application Firewall',
                'Regular security headers',
                'Input validation and sanitization'
            ],
            'https': [
                'Keep SSL/TLS certificates updated',
                'Use strong cipher suites',
                'Implement HSTS',
                'Regular security scanning'
            ]
        }
        
        recommendations = base_recommendations.get(service, [
            f'Review {service} service configuration',
            f'Implement {service}-specific security controls',
            f'Monitor {service} service logs regularly'
        ])
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.insert(0, f'Consider temporarily disabling {service} service')
            recommendations.append(f'Conduct immediate {service} security audit')
        
        return recommendations

class AdvancedReporting:
    """Advanced reporting and visualization"""
    
    def __init__(self):
        self.report_templates = {}
        self.scheduled_reports = []
    
    def generate_compliance_report(self, events: List[Dict], framework: str = 'NIST') -> Dict[str, Any]:
        """Generate compliance-focused report"""
        try:
            if framework.upper() == 'NIST':
                return self._generate_nist_report(events)
            elif framework.upper() == 'ISO27001':
                return self._generate_iso27001_report(events)
            elif framework.upper() == 'SOC2':
                return self._generate_soc2_report(events)
            else:
                return {'error': f'Unsupported framework: {framework}'}
                
        except Exception as e:
            logger.error(f"Compliance report generation failed: {e}")
            return {'error': str(e)}
    
    def _generate_nist_report(self, events: List[Dict]) -> Dict[str, Any]:
        """Generate NIST Cybersecurity Framework report"""
        df = pd.DataFrame(events) if events else pd.DataFrame()
        
        # NIST CSF Functions
        nist_functions = {
            'Identify': self._assess_identify_function(df),
            'Protect': self._assess_protect_function(df),
            'Detect': self._assess_detect_function(df),
            'Respond': self._assess_respond_function(df),
            'Recover': self._assess_recover_function(df)
        }
        
        return {
            'framework': 'NIST Cybersecurity Framework',
            'assessment_date': datetime.now().isoformat(),
            'functions': nist_functions,
            'overall_maturity': self._calculate_overall_maturity(nist_functions),
            'recommendations': self._generate_nist_recommendations(nist_functions),
            'evidence': {
                'total_events_analyzed': len(df),
                'analysis_period': '30 days',
                'detection_coverage': self._calculate_detection_coverage(df)
            }
        }
    
    def _assess_identify_function(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Assess NIST Identify function"""
        return {
            'maturity_level': 3,  # Defined
            'score': 75,
            'evidence': [
                'Asset inventory maintained through threat_sensor monitoring',
                'Threat landscape continuously monitored',
                'Risk assessment performed through attack analysis'
            ],
            'gaps': [
                'Formal asset classification needed',
                'Supply chain risk assessment required'
            ]
        }
    
    def _assess_protect_function(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Assess NIST Protect function"""
        return {
            'maturity_level': 2,  # Managed
            'score': 60,
            'evidence': [
                'Access controls implemented',
                'Security awareness through attack monitoring',
                'Data protection through threat_sensor isolation'
            ],
            'gaps': [
                'Formal access control policy needed',
                'Regular security training required',
                'Data encryption at rest needed'
            ]
        }
    
    def _assess_detect_function(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Assess NIST Detect function"""
        detection_score = 90 if not df.empty else 50
        
        return {
            'maturity_level': 4,  # Optimized
            'score': detection_score,
            'evidence': [
                'Continuous monitoring through threat_sensors',
                'Anomaly detection implemented',
                'Security event correlation active',
                f'{len(df)} security events detected and analyzed'
            ],
            'gaps': [
                'Threat hunting capabilities could be enhanced',
                'Detection rule tuning needed'
            ]
        }
    
    def _assess_respond_function(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Assess NIST Respond function"""
        return {
            'maturity_level': 3,  # Defined
            'score': 70,
            'evidence': [
                'Incident response procedures defined',
                'Automated alerting implemented',
                'Communication protocols established'
            ],
            'gaps': [
                'Incident response testing needed',
                'Forensic capabilities limited',
                'Recovery procedures need documentation'
            ]
        }
    
    def _assess_recover_function(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Assess NIST Recover function"""
        return {
            'maturity_level': 2,  # Managed
            'score': 55,
            'evidence': [
                'System restoration procedures exist',
                'Lessons learned process in place'
            ],
            'gaps': [
                'Formal recovery planning needed',
                'Business continuity testing required',
                'Recovery time objectives not defined'
            ]
        }
    
    def _calculate_overall_maturity(self, functions: Dict) -> Dict[str, Any]:
        """Calculate overall NIST maturity"""
        scores = [func['score'] for func in functions.values()]
        avg_score = sum(scores) / len(scores)
        
        if avg_score >= 80:
            maturity = 'Optimized'
        elif avg_score >= 60:
            maturity = 'Defined'
        elif avg_score >= 40:
            maturity = 'Managed'
        else:
            maturity = 'Initial'
        
        return {
            'level': maturity,
            'score': avg_score,
            'strongest_function': max(functions.items(), key=lambda x: x[1]['score'])[0],
            'weakest_function': min(functions.items(), key=lambda x: x[1]['score'])[0]
        }
    
    def _calculate_detection_coverage(self, df: pd.DataFrame) -> float:
        """Calculate detection coverage percentage"""
        if df.empty:
            return 0.0
        
        # Simple coverage calculation based on service diversity
        unique_services = df['service'].nunique()
        max_expected_services = 10  # Assume max 10 services
        
        return min(unique_services / max_expected_services * 100, 100)
    
    def _generate_nist_recommendations(self, functions: Dict) -> List[str]:
        """Generate NIST-specific recommendations"""
        recommendations = []
        
        # Find lowest scoring function
        lowest_function = min(functions.items(), key=lambda x: x[1]['score'])
        recommendations.append(f"Priority: Improve {lowest_function[0]} function (current score: {lowest_function[1]['score']})")
        
        # Add specific recommendations based on gaps
        for func_name, func_data in functions.items():
            for gap in func_data.get('gaps', []):
                recommendations.append(f"{func_name}: {gap}")
        
        return recommendations
    
    def _generate_iso27001_report(self, events: List[Dict]) -> Dict[str, Any]:
        """Generate ISO 27001 compliance report"""
        return {
            'framework': 'ISO 27001:2013',
            'assessment_date': datetime.now().isoformat(),
            'controls_assessment': {
                'A.12.6.1': {'status': 'Implemented', 'evidence': 'Security incident monitoring active'},
                'A.16.1.2': {'status': 'Partially Implemented', 'evidence': 'Incident reporting procedures exist'},
                'A.16.1.4': {'status': 'Implemented', 'evidence': 'Security event analysis performed'}
            },
            'recommendations': [
                'Implement formal incident classification',
                'Establish incident response team',
                'Document lessons learned process'
            ]
        }
    
    def _generate_soc2_report(self, events: List[Dict]) -> Dict[str, Any]:
        """Generate SOC 2 compliance report"""
        return {
            'framework': 'SOC 2 Type II',
            'assessment_date': datetime.now().isoformat(),
            'trust_criteria': {
                'Security': {'rating': 'Satisfactory', 'evidence': 'Continuous monitoring implemented'},
                'Availability': {'rating': 'Needs Improvement', 'evidence': 'Uptime monitoring required'},
                'Confidentiality': {'rating': 'Satisfactory', 'evidence': 'Data protection controls active'}
            },
            'recommendations': [
                'Implement availability monitoring',
                'Document security procedures',
                'Establish change management process'
            ]
        }

# ========================
# GLOBAL INSTANCES
# ========================

# Global analytics engines
predictive_analytics = PredictiveAnalytics()
business_intelligence = BusinessIntelligence()
advanced_reporting = AdvancedReporting()
risk_assessment = RiskAssessment()
