"""
Web API for Behavioral Anomaly Detection Dashboard
"""
import os
import sys
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import pandas as pd
from datetime import datetime, timedelta
import json
import math

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from ml.simple_anomaly_detector import SimpleAnomalyDetector
# from data.fake_data_generator import FakeDataGenerator

app = Flask(__name__, template_folder='../templates', static_folder='../static')
CORS(app)

# Global detector instance
detector = SimpleAnomalyDetector()
latest_results = []

def safe_value(value, default=""):
    """Convert NaN and None values to safe defaults"""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return default
    return value

def initialize_system():
    """Initialize the detection system with data"""
    global detector, latest_results
    
    try:
        # Check if we have training data
        data_path = os.path.join(parent_dir, 'data', 'user_behavior.csv')
        if not os.path.exists(data_path):
            print("📊 No training data found. Generating...")
            generator = FakeDataGenerator()
            generator.generate_dataset()
            
        # Train the detector
        print("🧠 Training detector...")
        detector.train(data_path)
        
        # Run analysis
        print("🔍 Running analysis...")
        latest_results = detector.batch_analyze(data_path)
        
        print(f"✅ System initialized successfully! Found {len(latest_results)} events")
        return True
        
    except Exception as e:
        print(f"❌ Error initializing system: {e}")
        import traceback
        traceback.print_exc()
        return False

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Get current alerts"""
    try:
        print(f"📊 API /alerts called. Have {len(latest_results)} results")
        
        if not latest_results:
            return jsonify({'error': 'No data available', 'alerts': [], 'total_alerts': 0}), 200
            
        # Get suspicious events only
        suspicious_events = [r for r in latest_results if r.get('is_suspicious', False)]
        print(f"🚨 Found {len(suspicious_events)} suspicious events")
        
        # Sort by risk score (highest first)
        suspicious_events.sort(key=lambda x: x.get('overall_risk_score', 0), reverse=True)
        
        # Format for frontend
        alerts = []
        for i, result in enumerate(suspicious_events[:20]):  # Top 20 alerts
            event = result.get('event', {})
            alerts.append({
                'id': i + 1,
                'user_name': safe_value(event.get('user_name'), 'Unknown'),
                'timestamp': safe_value(event.get('timestamp'), ''),
                'risk_score': round(result.get('overall_risk_score', 0), 2),
                'alert_level': result.get('alert_level', 'LOW'),
                'event_type': safe_value(event.get('event_type'), 'unknown'),
                'location': safe_value(event.get('location'), 'Unknown'),
                'country': safe_value(event.get('country'), 'Unknown'),
                'source_ip': safe_value(event.get('source_ip'), 'Unknown'),
                'anomalies': result.get('anomalies', [])[:3],  # Top 3 issues
                'file_name': safe_value(event.get('file_name'), ''),
                'file_size_mb': safe_value(event.get('file_size_mb'), 0)
            })
            
        response_data = {
            'alerts': alerts,
            'total_alerts': len(suspicious_events),
            'high_risk': len([a for a in alerts if a['alert_level'] == 'HIGH']),
            'medium_risk': len([a for a in alerts if a['alert_level'] == 'MEDIUM']),
            'low_risk': len([a for a in alerts if a['alert_level'] == 'LOW'])
        }
        
        print(f"✅ Returning {len(alerts)} alerts")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"❌ Error in /api/alerts: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'alerts': [], 'total_alerts': 0}), 500

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    try:
        print(f"📈 API /stats called. Have {len(latest_results)} results")
        
        if not latest_results:
            return jsonify({'error': 'No data available'}), 500
            
        total_events = len(latest_results)
        suspicious_events = len([r for r in latest_results if r.get('is_suspicious', False)])
        
        # User statistics
        user_stats = {}
        for result in latest_results:
            user_name = safe_value(result.get('event', {}).get('user_name'), 'Unknown')
            if user_name not in user_stats:
                user_stats[user_name] = {'total': 0, 'suspicious': 0}
            user_stats[user_name]['total'] += 1
            if result.get('is_suspicious', False):
                user_stats[user_name]['suspicious'] += 1
                
        # Alert levels
        alert_levels = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NORMAL': 0}
        for result in latest_results:
            level = result.get('alert_level', 'NORMAL')
            alert_levels[level] += 1
            
        response_data = {
            'total_events': total_events,
            'suspicious_events': suspicious_events,
            'detection_rate': round((suspicious_events / total_events) * 100, 1) if total_events > 0 else 0,
            'user_stats': user_stats,
            'alert_levels': alert_levels,
            'last_updated': datetime.now().isoformat()
        }
        
        print(f"✅ Stats: {total_events} total, {suspicious_events} suspicious")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"❌ Error in /api/stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Behavioral Anomaly Detection Dashboard...")
    
    # Initialize the system
    if initialize_system():
        print("🌐 Dashboard available at: http://localhost:5000")
        print("🔍 Check browser console (F12) for any JavaScript errors")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("❌ Failed to start dashboard")

@app.route('/api/real-data/start')
def start_real_monitoring():
    """Start real-time data monitoring"""
    try:
        global data_manager
        from data.data_source_manager import create_data_manager
        
        data_manager = create_data_manager()
        data_manager.start_all_connectors()
        
        return jsonify({'message': 'Real-time monitoring started', 'status': 'success'})
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'failed'}), 500

@app.route('/api/real-data/stop')
def stop_real_monitoring():
    """Stop real-time data monitoring"""
    try:
        global data_manager
        if 'data_manager' in globals():
            data_manager.stop_all_connectors()
            data_manager.export_events("data/real_events.csv")
            
        return jsonify({'message': 'Real-time monitoring stopped', 'status': 'success'})
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'failed'}), 500

@app.route('/api/real-data/status')
def real_data_status():
    """Get real-time data monitoring status"""
    try:
        if 'data_manager' not in globals():
            return jsonify({'status': 'stopped', 'stats': {}})
            
        stats = data_manager.get_stats()
        stats['status'] = 'running' if data_manager.is_running else 'stopped'
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/real-data/events')
def get_real_events():
    """Get recent real events"""
    try:
        if 'data_manager' not in globals():
            return jsonify({'events': []})
            
        recent_events = data_manager.get_recent_events(minutes=60)
        
        return jsonify({
            'events': recent_events[:50],  # Last 50 events
            'total': len(recent_events)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-data', methods=['POST'])
def upload_data():
    """Upload custom CSV data for analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if file and file.filename.endswith('.csv'):
            # Save uploaded file
            filepath = os.path.join(parent_dir, 'data', 'uploaded_data.csv')
            file.save(filepath)
            
            # Analyze the uploaded data
            global detector, latest_results
            detector = SimpleAnomalyDetector()
            detector.train(filepath)
            latest_results = detector.batch_analyze(filepath)
            
            return jsonify({
                'message': 'File uploaded and analyzed successfully',
                'total_events': len(latest_results),
                'suspicious_events': len([r for r in latest_results if r['is_suspicious']])
            })
        else:
            return jsonify({'error': 'Please upload a CSV file'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for Docker"""
    return jsonify({
        'status': 'healthy',
        'service': 'anomaly-detector',
        'timestamp': datetime.now().isoformat()
    })
