"""
File System Monitor Connector
Monitors file system for suspicious file access patterns
"""
import os
from datetime import datetime
from typing import Dict, Iterator
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
import mimetypes

from .base_connector import BaseConnector

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, connector):
        self.connector = connector
        self.suspicious_extensions = ['.sql', '.db', '.key', '.pem', '.config']
        
    def on_moved(self, event):
        if not event.is_directory:
            self.connector.queue_file_event('file_moved', event.src_path, event.dest_path)
            
    def on_created(self, event):
        if not event.is_directory:
            self.connector.queue_file_event('file_created', event.src_path)
            
    def on_deleted(self, event):
        if not event.is_directory:
            self.connector.queue_file_event('file_deleted', event.src_path)
            
    def on_modified(self, event):
        if not event.is_directory:
            self.connector.queue_file_event('file_modified', event.src_path)

class FileMonitorConnector(BaseConnector):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.watch_directories = config.get('watch_directories', ['/tmp'])
        self.file_extensions = config.get('file_extensions', [])
        self.observer = None
        self.file_events = []
        
    def connect(self) -> bool:
        """Setup file system monitoring"""
        try:
            self.observer = Observer()
            handler = FileEventHandler(self)
            
            # Add watchers for each directory
            for directory in self.watch_directories:
                if os.path.exists(directory):
                    self.observer.schedule(handler, directory, recursive=True)
                    print(f"📁 Watching directory: {directory}")
                    
            return True
            
        except Exception as e:
            print(f"Error setting up file monitoring: {e}")
            return False
            
    def start_monitoring(self):
        """Start file system monitoring"""
        if self.observer and not self.observer.is_alive():
            self.observer.start()
        super().start_monitoring()
        
    def stop_monitoring(self):
        """Stop file system monitoring"""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        super().stop_monitoring()
        
    def queue_file_event(self, event_type: str, file_path: str, dest_path: str = None):
        """Queue a file system event"""
        try:
            # Get file info
            file_size = 0
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                
            # Create event
            event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'file_access',
                'action': event_type,
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size_mb': round(file_size / (1024 * 1024), 2),
                'file_extension': file_ext,
                'dest_path': dest_path,
                'user_name': self._get_file_owner(file_path)
            }
            
            self.file_events.append(event)
            
        except Exception as e:
            print(f"Error queuing file event: {e}")
            
    def _get_file_owner(self, file_path: str) -> str:
        """Get file owner username"""
        try:
            import pwd
            file_stat = os.stat(file_path)
            owner = pwd.getpwuid(file_stat.st_uid).pw_name
            return owner
        except:
            return 'unknown'
            
    def fetch_events(self) -> Iterator[Dict]:
        """Get queued file events"""
        while self.file_events:
            yield self.file_events.pop(0)
            
    def parse_event(self, raw_event: Dict) -> Dict:
        """Parse file system event"""
        try:
            return self.standardize_event(raw_event)
        except Exception as e:
            print(f"Error parsing file event: {e}")
            return None
