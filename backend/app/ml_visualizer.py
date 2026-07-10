"""
SentinelGrid ML Visualization
Creates charts and visualizations for ML model performance and predictions
"""
import logging
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import Dict, List, Any
from pathlib import Path
import base64
from io import BytesIO
from .ml_engine import ModelMetrics

logger = logging.getLogger(__name__)

class MLVisualizer:
    """Create visualizations for ML model performance"""
    
    def __init__(self):
        self.output_dir = Path("reports/ml_charts")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def create_model_performance_chart(self, metrics: ModelMetrics) -> str:
        """Create model performance visualization"""
        try:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle(f'ML Model Performance - Version {metrics.model_version}', fontsize=16)
            
            # 1. Performance Metrics Bar Chart
            performance_metrics = {
                'Accuracy': metrics.accuracy,
                'Precision': metrics.precision,
                'Recall': metrics.recall,
                'F1-Score': metrics.f1_score,
                'AUC Score': metrics.auc_score
            }
            
            bars = ax1.bar(performance_metrics.keys(), performance_metrics.values())
            ax1.set_title('Model Performance Metrics')
            ax1.set_ylabel('Score')
            ax1.set_ylim(0, 1)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                        f'{height:.3f}', ha='center', va='bottom')
            
            # 2. Confusion Matrix
            cm = np.array(metrics.confusion_matrix)
            if cm.size > 0:
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax2)
                ax2.set_title('Confusion Matrix')
                ax2.set_xlabel('Predicted')
                ax2.set_ylabel('Actual')
            
            # 3. Feature Importance (Top 10)
            if metrics.feature_importance:
                top_features = dict(sorted(
                    metrics.feature_importance.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10])
                
                ax3.barh(list(top_features.keys()), list(top_features.values()))
                ax3.set_title('Top 10 Feature Importance')
                ax3.set_xlabel('Importance Score')
            
            # 4. Training Information
            info_text = f"""
            Model Version: {metrics.model_version}
            Training Samples: {metrics.training_samples}
            Last Trained: {metrics.last_trained[:19]}
            
            Performance Summary:
            • Accuracy: {metrics.accuracy:.3f}
            • F1-Score: {metrics.f1_score:.3f}
            • AUC Score: {metrics.auc_score:.3f}
            """
            
            ax4.text(0.1, 0.5, info_text, transform=ax4.transAxes,
                    fontsize=12, verticalalignment='center',
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="lightblue"))
            ax4.set_xlim(0, 1)
            ax4.set_ylim(0, 1)
            ax4.axis('off')
            ax4.set_title('Model Information')
            
            plt.tight_layout()
            
            # Save chart
            chart_path = self.output_dir / f"model_performance_{metrics.model_version}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Model performance chart saved: {chart_path}")
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Failed to create performance chart: {e}")
            return ""
    
    def create_threat_distribution_chart(self, predictions: List[Dict]) -> str:
        """Create threat level distribution chart"""
        try:
            if not predictions:
                return ""
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            fig.suptitle('Threat Detection Analysis', fontsize=16)
            
            # Extract data
            threat_levels = [p.get('threat_level', 'UNKNOWN') for p in predictions]
            confidences = [p.get('confidence', 0.0) for p in predictions]
            
            # 1. Threat Level Distribution
            threat_counts = pd.Series(threat_levels).value_counts()
            colors = ['green', 'yellow', 'orange', 'red', 'darkred'][:len(threat_counts)]
            
            wedges, texts, autotexts = ax1.pie(
                threat_counts.values,
                labels=threat_counts.index,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            ax1.set_title('Threat Level Distribution')
            
            # 2. Confidence Distribution
            ax2.hist(confidences, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            ax2.set_title('Prediction Confidence Distribution')
            ax2.set_xlabel('Confidence Score')
            ax2.set_ylabel('Frequency')
            ax2.axvline(np.mean(confidences), color='red', linestyle='--', 
                       label=f'Mean: {np.mean(confidences):.3f}')
            ax2.legend()
            
            plt.tight_layout()
            
            # Save chart
            chart_path = self.output_dir / "threat_distribution.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Threat distribution chart saved: {chart_path}")
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Failed to create threat distribution chart: {e}")
            return ""
    
    def create_anomaly_detection_chart(self, events: List[Dict], predictions: List[Dict]) -> str:
        """Create anomaly detection visualization"""
        try:
            if not events or not predictions:
                return ""
            
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
            fig.suptitle('Anomaly Detection Analysis', fontsize=16)
            
            # Extract data
            timestamps = [e.get('timestamp', '') for e in events]
            anomaly_scores = [p.get('anomaly_score', 0.0) for p in predictions]
            threat_levels = [p.get('threat_level', 'UNKNOWN') for p in predictions]
            
            # Convert timestamps to datetime
            try:
                timestamps = pd.to_datetime(timestamps)
            except:
                timestamps = range(len(anomaly_scores))
            
            # 1. Anomaly Scores Over Time
            colors = ['green' if level in ['LOW', 'BENIGN'] else 
                     'yellow' if level == 'MEDIUM' else 
                     'orange' if level == 'HIGH' else 'red' 
                     for level in threat_levels]
            
            scatter = ax1.scatter(timestamps, anomaly_scores, c=colors, alpha=0.6)
            ax1.set_title('Anomaly Scores Over Time')
            ax1.set_ylabel('Anomaly Score')
            ax1.axhline(y=0, color='black', linestyle='-', alpha=0.3)
            ax1.axhline(y=-0.5, color='red', linestyle='--', alpha=0.5, label='Anomaly Threshold')
            ax1.legend()
            
            # 2. Anomaly Score Distribution
            ax2.hist(anomaly_scores, bins=30, alpha=0.7, color='lightcoral', edgecolor='black')
            ax2.set_title('Anomaly Score Distribution')
            ax2.set_xlabel('Anomaly Score')
            ax2.set_ylabel('Frequency')
            ax2.axvline(np.mean(anomaly_scores), color='blue', linestyle='--', 
                       label=f'Mean: {np.mean(anomaly_scores):.3f}')
            ax2.axvline(-0.5, color='red', linestyle='--', alpha=0.7, label='Anomaly Threshold')
            ax2.legend()
            
            plt.tight_layout()
            
            # Save chart
            chart_path = self.output_dir / "anomaly_detection.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Anomaly detection chart saved: {chart_path}")
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Failed to create anomaly detection chart: {e}")
            return ""
    
    def create_feature_analysis_chart(self, feature_importance: Dict[str, float]) -> str:
        """Create detailed feature analysis chart"""
        try:
            if not feature_importance:
                return ""
            
            # Sort features by importance
            sorted_features = dict(sorted(
                feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            ))
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 8))
            fig.suptitle('Feature Importance Analysis', fontsize=16)
            
            # 1. Top 15 Features Bar Chart
            top_15 = dict(list(sorted_features.items())[:15])
            bars = ax1.barh(list(top_15.keys()), list(top_15.values()))
            ax1.set_title('Top 15 Most Important Features')
            ax1.set_xlabel('Importance Score')
            
            # Add value labels
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax1.text(width + 0.001, bar.get_y() + bar.get_height()/2,
                        f'{width:.3f}', ha='left', va='center')
            
            # 2. Feature Importance Distribution
            importance_values = list(sorted_features.values())
            ax2.hist(importance_values, bins=20, alpha=0.7, color='lightgreen', edgecolor='black')
            ax2.set_title('Feature Importance Distribution')
            ax2.set_xlabel('Importance Score')
            ax2.set_ylabel('Number of Features')
            ax2.axvline(np.mean(importance_values), color='red', linestyle='--',
                       label=f'Mean: {np.mean(importance_values):.4f}')
            ax2.legend()
            
            plt.tight_layout()
            
            # Save chart
            chart_path = self.output_dir / "feature_analysis.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"Feature analysis chart saved: {chart_path}")
            return str(chart_path)
            
        except Exception as e:
            logger.error(f"Failed to create feature analysis chart: {e}")
            return ""
    
    def chart_to_base64(self, chart_path: str) -> str:
        """Convert chart to base64 string for web display"""
        try:
            if not chart_path or not Path(chart_path).exists():
                return ""
            
            with open(chart_path, 'rb') as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode()
                return f"data:image/png;base64,{encoded_string}"
                
        except Exception as e:
            logger.error(f"Failed to convert chart to base64: {e}")
            return ""
    
    def create_ml_dashboard_data(self, metrics: ModelMetrics, 
                                predictions: List[Dict], 
                                events: List[Dict]) -> Dict[str, Any]:
        """Create comprehensive ML dashboard data"""
        try:
            # Create all charts
            performance_chart = self.create_model_performance_chart(metrics)
            threat_chart = self.create_threat_distribution_chart(predictions)
            anomaly_chart = self.create_anomaly_detection_chart(events, predictions)
            feature_chart = self.create_feature_analysis_chart(metrics.feature_importance)
            
            # Convert to base64 for web display
            dashboard_data = {
                "model_info": {
                    "version": metrics.model_version,
                    "accuracy": metrics.accuracy,
                    "f1_score": metrics.f1_score,
                    "training_samples": metrics.training_samples,
                    "last_trained": metrics.last_trained
                },
                "charts": {
                    "performance": self.chart_to_base64(performance_chart),
                    "threat_distribution": self.chart_to_base64(threat_chart),
                    "anomaly_detection": self.chart_to_base64(anomaly_chart),
                    "feature_analysis": self.chart_to_base64(feature_chart)
                },
                "statistics": {
                    "total_predictions": len(predictions),
                    "high_confidence_predictions": sum(1 for p in predictions if p.get('confidence', 0) > 0.8),
                    "anomalies_detected": sum(1 for p in predictions if p.get('anomaly_score', 0) < -0.5),
                    "threat_levels": self._get_threat_level_stats(predictions)
                }
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Failed to create ML dashboard data: {e}")
            return {"error": str(e)}
    
    def _get_threat_level_stats(self, predictions: List[Dict]) -> Dict[str, int]:
        """Get threat level statistics"""
        stats = {}
        for prediction in predictions:
            level = prediction.get('threat_level', 'UNKNOWN')
            stats[level] = stats.get(level, 0) + 1
        return stats

# Global visualizer instance
ml_visualizer = MLVisualizer()
