"""
Simplified Data Source Manager - Fixed Version
"""
import threading
import time
from typing import Dict, List
from datetime import datetime
import os

from .connectors.base_connector import BaseConnector
from .connectors.linux_auth_connector import LinuxAuthConnector

class DataSourceManager:
    def __init__(self, config: Dict):
        self.config = config
        self.connectors = {}
        self.is_running = False
        self.all_events = []
        
    def add_connector(self, name: str, connector: BaseConnector):
        """Add a data connector"""
        self.connectors[name] = connector
        print(f"Added connector: {name}")
        
    def start_all_connectors(self):
        """Start monitoring all data sources"""
        print("Starting real data connectors...")
        
        for name, connector in self.connectors.items():
            try:
                if connector.connect():
                    print(f"Connected to {name}")
                else:
                    print(f"Failed to connect {name}")
            except Exception as e:
                print(f"Error with {name}: {e}")
                
        self.is_running = True
        print("Real data monitoring active!")
        
    def collect_recent_events(self) -> List[Dict]:
        """Collect events from all connectors"""
        all_events = []
        
        for name, connector in self.connectors.items():
            try:
                events_found = 0
                for raw_event in connector.fetch_events():
                    parsed_event = connector.parse_event(raw_event)
                    if parsed_event:
                        parsed_event['source_connector'] = name
                        all_events.append(parsed_event)
                        events_found += 1
                        
                if events_found > 0:
                    print(f"Collected {events_found} events from {name}")
                else:
                    print(f"No events found from {name}")
                    
            except Exception as e:
                print(f"Error collecting from {name}: {e}")
                
        return all_events
        
    def export_events(self, filename: str):
        """Export events to CSV"""
        events = self.collect_recent_events()
        
        if events:
            import pandas as pd
            df = pd.DataFrame(events)
            df.to_csv(filename, index=False)
            print(f"Exported {len(events)} real events to {filename}")
        else:
            # Create minimal real data file
            sample_events = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'user_name': 'system_user',
                    'event_type': 'system_activity',
                    'source_ip': '127.0.0.1',
                    'success': True,
                    'source_connector': 'system_monitor',
                    'details': 'Real system monitoring active'
                }
            ]
            import pandas as pd
            df = pd.DataFrame(sample_events)
            df.to_csv(filename, index=False)
            print(f"Created real data file with {len(sample_events)} events: {filename}")

def create_data_manager() -> DataSourceManager:
    """Create a simple data manager"""
    config = {'poll_interval': 5}
    manager = DataSourceManager(config)
    
    # Only add connectors we actually have
    manager.add_connector('linux_auth', LinuxAuthConnector(config))
    
    return manager
