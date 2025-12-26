"""
Base connector class for all data sources
"""
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Iterator
import threading
import queue
import time

logger = logging.getLogger(__name__)

class BaseConnector(ABC):
    def __init__(self, config: Dict):
        self.config = config
        self.is_running = False
        self.event_queue = queue.Queue()
        self.worker_thread = None
        
    @abstractmethod
    def connect(self) -> bool:
        pass
        
    @abstractmethod
    def parse_event(self, raw_event: str) -> Dict:
        pass
        
    @abstractmethod
    def fetch_events(self) -> Iterator[str]:
        pass
        
    def start_monitoring(self):
        if self.is_running:
            return
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._monitor_loop)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        logger.info(f"Started monitoring {self.__class__.__name__}")
        
    def stop_monitoring(self):
        self.is_running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info(f"Stopped monitoring {self.__class__.__name__}")
        
    def _monitor_loop(self):
        while self.is_running:
            try:
                for raw_event in self.fetch_events():
                    if not self.is_running:
                        break
                    parsed_event = self.parse_event(raw_event)
                    if parsed_event:
                        self.event_queue.put(parsed_event)
                time.sleep(self.config.get('poll_interval', 5))
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
                
    def get_events(self) -> List[Dict]:
        events = []
        while not self.event_queue.empty():
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events
        
    def standardize_event(self, event_data: Dict) -> Dict:
        return {
            'timestamp': event_data.get('timestamp', datetime.now().isoformat()),
            'user_id': event_data.get('user_id'),
            'user_name': event_data.get('user_name'),
            'event_type': event_data.get('event_type'),
            'source_ip': event_data.get('source_ip'),
            'location': event_data.get('location', 'Unknown'),
            'country': event_data.get('country', 'Unknown'),
            'device': event_data.get('device'),
            'success': event_data.get('success', True),
            'file_name': event_data.get('file_name'),
            'file_size_mb': event_data.get('file_size_mb'),
            'action': event_data.get('action'),
            'details': event_data.get('details', {}),
            'source': self.__class__.__name__
        }
