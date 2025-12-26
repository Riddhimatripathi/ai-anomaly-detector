"""
Linux Authentication Log Connector
Monitors /var/log/auth.log and /var/log/secure for SSH, sudo, login events
"""
import re
import os
from datetime import datetime
from typing import Dict, Iterator
import subprocess
import socket

from .base_connector import BaseConnector

class LinuxAuthConnector(BaseConnector):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.log_files = config.get('log_files', ['/var/log/auth.log', '/var/log/secure'])
        self.last_positions = {}
        self.hostname = socket.gethostname()
        
    def connect(self) -> bool:
        """Check if log files exist and are readable"""
        try:
            accessible_files = []
            for log_file in self.log_files:
                if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                    accessible_files.append(log_file)
                    self.last_positions[log_file] = self._get_file_size(log_file)
                    
            self.log_files = accessible_files
            return len(self.log_files) > 0
            
        except Exception as e:
            print(f"Error connecting to Linux auth logs: {e}")
            return False
            
    def _get_file_size(self, file_path: str) -> int:
        """Get current file size"""
        try:
            return os.path.getsize(file_path)
        except:
            return 0
    
    def fetch_events(self) -> Iterator[str]:
        """Fetch new log entries"""
        for log_file in self.log_files:
            try:
                current_size = self._get_file_size(log_file)
                last_position = self.last_positions.get(log_file, 0)
                
                if current_size > last_position:
                    with open(log_file, 'r') as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        
                    self.last_positions[log_file] = current_size
                    
                    for line in new_lines:
                        yield line.strip()
                        
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
                
    def parse_event(self, raw_event: str) -> Dict:
        """Parse auth log entry"""
        try:
            # SSH login patterns
            ssh_login_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*for (\w+) from ([\d\.]+)'
            ssh_failed_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed.*for (\w+) from ([\d\.]+)'
            sudo_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*(\w+).*COMMAND=(.*)'
            
            # Try SSH successful login
            match = re.search(ssh_login_pattern, raw_event)
            if match:
                timestamp_str, username, source_ip = match.groups()
                return self.standardize_event({
                    'timestamp': self._parse_timestamp(timestamp_str),
                    'user_name': username,
                    'event_type': 'login',
                    'source_ip': source_ip,
                    'success': True,
                    'details': {'method': 'ssh', 'raw': raw_event}
                })
                
            # Try SSH failed login
            match = re.search(ssh_failed_pattern, raw_event)
            if match:
                timestamp_str, username, source_ip = match.groups()
                return self.standardize_event({
                    'timestamp': self._parse_timestamp(timestamp_str),
                    'user_name': username,
                    'event_type': 'login',
                    'source_ip': source_ip,
                    'success': False,
                    'details': {'method': 'ssh', 'raw': raw_event}
                })
                
            # Try sudo command
            match = re.search(sudo_pattern, raw_event)
            if match:
                timestamp_str, username, command = match.groups()
                return self.standardize_event({
                    'timestamp': self._parse_timestamp(timestamp_str),
                    'user_name': username,
                    'event_type': 'command',
                    'action': 'sudo',
                    'details': {'command': command.strip(), 'raw': raw_event}
                })
                
        except Exception as e:
            print(f"Error parsing auth event: {e}")
            
        return None
        
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse syslog timestamp to ISO format"""
        try:
            # Add current year since syslog doesn't include it
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            dt = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except:
            return datetime.now().isoformat()
