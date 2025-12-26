import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ml.simple_anomaly_detector import SimpleAnomalyDetector

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, detector):
        self.detector = detector
        
    def on_created(self, event):
        if event.src_path.endswith('.csv'):
            print(f"📁 New file: {event.src_path}")
            self.analyze_file(event.src_path)
            
    def analyze_file(self, filepath):
        try:
            print(f"🔍 Analyzing...")
            results = self.detector.batch_analyze(filepath)
            suspicious = [r for r in results if r['is_suspicious']]
            if suspicious:
                print(f"🚨 ALERT! {len(suspicious)} threats found")
                for r in suspicious[:3]:
                    print(f"   ⚠️ {r['event'].get('user_name')}: Risk {r['overall_risk_score']:.2f}")
            else:
                print(f"✅ No threats")
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🚀 Real-Time Monitor Started")
    os.makedirs('data/incoming', exist_ok=True)
    detector = SimpleAnomalyDetector()
    detector.train('data/user_behavior.csv')
    event_handler = LogFileHandler(detector)
    observer = Observer()
    observer.schedule(event_handler, 'data/incoming', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n⏹️ Stopped")
    observer.join()

