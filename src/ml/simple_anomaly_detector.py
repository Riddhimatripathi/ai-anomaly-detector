"""
Simple anomaly detection using basic rules and machine learning
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
import json


class SimpleAnomalyDetector:
    def __init__(self):
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.user_profiles = {}
        self.suspicious_countries = ["Russia", "China", "North Korea", "Unknown"]
        
    def create_user_profiles(self, df: pd.DataFrame):
        """Create behavioral profiles for each user"""
        profiles = {}
        
        for user_id in df['user_id'].unique():
            user_data = df[df['user_id'] == user_id].copy()
            
            # Convert timestamps
            user_data['timestamp'] = pd.to_datetime(user_data['timestamp'])
            user_data['hour'] = user_data['timestamp'].dt.hour
            user_data['day_of_week'] = user_data['timestamp'].dt.dayofweek
            
            login_data = user_data[user_data['event_type'] == 'login']
            file_data = user_data[user_data['event_type'] == 'file_access']
            
            profile = {
                'user_id': int(user_id),
                'name': user_data['user_name'].iloc[0] if 'user_name' in user_data else f"User {user_id}",
                'normal_login_hours': {
                    'min': int(login_data['hour'].min()) if len(login_data) > 0 else 9,
                    'max': int(login_data['hour'].max()) if len(login_data) > 0 else 17,
                    'avg': float(login_data['hour'].mean()) if len(login_data) > 0 else 13
                },
                'normal_countries': list(user_data['country'].unique()) if 'country' in user_data else ['United States'],
                'normal_locations': list(user_data['location'].unique()) if 'location' in user_data else ['Unknown'],
                'avg_files_per_day': float(len(file_data) / 30) if len(file_data) > 0 else 0,
                'typical_file_sizes': {
                    'avg': float(file_data['file_size_mb'].mean()) if len(file_data) > 0 and 'file_size_mb' in file_data else 0,
                    'max': float(file_data['file_size_mb'].max()) if len(file_data) > 0 and 'file_size_mb' in file_data else 0
                }
            }
            
            profiles[user_id] = profile
            
        return profiles
    
    def train(self, csv_file: str):
        """Train the anomaly detection model"""
        print("🧠 Training anomaly detection model...")
        
        # Load data
        df = pd.read_csv(csv_file)
        print(f"📊 Loaded {len(df)} events")
        
        # Create user profiles
        self.user_profiles = self.create_user_profiles(df)
        print(f"👥 Created profiles for {len(self.user_profiles)} users")
        
        print("✅ Model training completed!")
        
    def detect_rule_based_anomalies(self, event):
        """Detect anomalies using simple rules - MORE AGGRESSIVE"""
        anomalies = []
        user_id = event.get('user_id')
        
        if user_id not in self.user_profiles:
            return ["Unknown user"]
            
        profile = self.user_profiles[user_id]
        
        # Check login time - MORE SENSITIVE
        if event.get('event_type') == 'login':
            try:
                timestamp_str = str(event['timestamp'])
                if 'T' in timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = pd.to_datetime(timestamp_str)
                hour = timestamp.hour
                
                # More aggressive time checking
                normal_start = profile['normal_login_hours']['min']
                normal_end = profile['normal_login_hours']['max']
                
                if hour < 6 or hour > 22:  # Very late/early hours
                    anomalies.append(f"Very unusual login time: {hour}:00")
                elif hour < normal_start - 1 or hour > normal_end + 1:
                    anomalies.append(f"Outside normal hours: {hour}:00 (normal: {normal_start}-{normal_end})")
                    
                # Check for suspicious country
                country = event.get('country', 'Unknown')
                if country in self.suspicious_countries:
                    anomalies.append(f"Login from suspicious country: {country}")
                    
                # Check for new location - MORE SENSITIVE
                location = event.get('location', 'Unknown')
                if location not in profile['normal_locations'] and location not in ['New York', 'California', 'Texas', 'Florida', 'Illinois']:
                    anomalies.append(f"Login from unusual location: {location}")
                    
                # Check IP pattern
                source_ip = event.get('source_ip', '')
                if not source_ip.startswith('192.168.1.'):
                    anomalies.append(f"Login from external IP: {source_ip}")
                    
            except Exception as e:
                anomalies.append(f"Error parsing timestamp: {e}")
        
        # Check file access - MORE SENSITIVE
        if event.get('event_type') == 'file_access':
            file_size = event.get('file_size_mb', 0)
            
            # Lower threshold for large files
            if file_size > 100:
                anomalies.append(f"Large file access: {file_size}MB")
                
            # Check for downloads
            if event.get('action') == 'download' and file_size > 50:
                anomalies.append(f"File download: {file_size}MB")
                
            # Check for database files
            file_name = event.get('file_name', '')
            if any(word in file_name.lower() for word in ['database', 'customer', 'entire', 'backup', '.sql']):
                anomalies.append(f"Sensitive file access: {file_name}")
        
        return anomalies
    
    def analyze_event(self, event):
        """Analyze a single event for anomalies"""
        # Rule-based detection
        rule_anomalies = self.detect_rule_based_anomalies(event)
        
        # Calculate overall risk score - MORE SENSITIVE
        rule_score = len(rule_anomalies) * 0.4  # Each rule violation adds more
        overall_score = min(1.0, rule_score)
        
        # Lower thresholds for alerts
        if overall_score >= 0.6:
            alert_level = "HIGH"
        elif overall_score >= 0.4:
            alert_level = "MEDIUM" 
        elif overall_score >= 0.2:  # Lower threshold
            alert_level = "LOW"
        else:
            alert_level = "NORMAL"
        
        return {
            'event': event,
            'anomalies': rule_anomalies,
            'overall_risk_score': overall_score,
            'alert_level': alert_level,
            'is_suspicious': overall_score >= 0.4,  # Lower threshold
            'timestamp_analyzed': datetime.now().isoformat()
        }
    
    def batch_analyze(self, csv_file: str):
        """Analyze multiple events from CSV file"""
        df = pd.read_csv(csv_file)
        results = []
        
        print(f"🔍 Analyzing {len(df)} events for anomalies...")
        
        for _, event in df.iterrows():
            result = self.analyze_event(event.to_dict())
            results.append(result)
            
        # Summary
        suspicious_count = sum(1 for r in results if r['is_suspicious'])
        print(f"🚨 Found {suspicious_count} suspicious events out of {len(results)} total")
        
        return results


if __name__ == "__main__":
    detector = SimpleAnomalyDetector()
    detector.train("../data/user_behavior.csv")
    results = detector.batch_analyze("../data/user_behavior.csv")
    
    suspicious = [r for r in results if r['is_suspicious']]
    print(f"\n🚨 Top 5 Most Suspicious Events:")
    for i, result in enumerate(sorted(suspicious, key=lambda x: x['overall_risk_score'], reverse=True)[:5]):
        print(f"\n{i+1}. User: {result['event'].get('user_name', 'Unknown')}")
        print(f"   Risk Score: {result['overall_risk_score']:.2f}")
        print(f"   Alert Level: {result['alert_level']}")
        print(f"   Issues: {', '.join(result['anomalies'])}")
