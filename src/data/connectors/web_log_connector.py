"""
Web Server Access Log Connector
Monitors Apache/Nginx access logs for user activity
"""
import re
import os
from datetime import datetime
from typing import Dict, Iterator
from urllib.parse import unquote
import geoip2.database
import geoip2.errors

from .base_connector import BaseConnector

class WebLogConnector(BaseConnector):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.log_files = config.get('log_files', [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/httpd/access_log'
        ])
        self.last_positions = {}
        
        # Common log format pattern
        self.log_pattern = re.compile(
            r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
        )
        
    def connect(self) -> bool:
        """Check if web log files exist"""
        try:
            accessible_files = []
            for log_file in self.log_files:
                if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                    accessible_files.append(log_file)
                    self.last_positions[log_file] = self._get_file_size(log_file)
                    
            self.log_files = accessible_files
            return len(self.log_files) > 0
            
        except Exception as e:
            print(f"Error connecting to web logs: {e}")
            return False
            
    def _get_file_size(self, file_path: str) -> int:
        """Get current file size"""
        try:
            return os.path.getsize(file_path)
        except:
            return 0
    
    def fetch_events(self) -> Iterator[str]:
        """Fetch new web log entries"""
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
        """Parse web access log entry"""
        try:
            match = self.log_pattern.match(raw_event)
            if not match:
                return None
                
            ip, timestamp_str, method, url, protocol, status_code, size, referer, user_agent = match.groups()
            
            # Skip static files and bots
            if self._is_static_file(url) or self._is_bot(user_agent):
                return None
                
            # Extract user activity
            event_type = self._determine_event_type(method, url, status_code)
            if not event_type:
                return None
                
            return self.standardize_event({
                'timestamp': self._parse_timestamp(timestamp_str),
                'user_name': self._extract_user_from_url(url),
                'event_type': event_type,
                'source_ip': ip,
                'success': int(status_code) < 400,
                'details': {
                    'method': method,
                    'url': url,
                    'status_code': status_code,
                    'user_agent': user_agent,
                    'size': size,
                    'raw': raw_event
                }
            })
            
        except Exception as e:
            print(f"Error parsing web log: {e}")
            
        return None
        
    def _is_static_file(self, url: str) -> bool:
        """Check if URL is for static content"""
        static_extensions = ['.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg', '.woff']
        return any(url.lower().endswith(ext) for ext in static_extensions)
        
    def _is_bot(self, user_agent: str) -> bool:
        """Check if user agent is a bot"""
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper']
        return any(indicator in user_agent.lower() for indicator in bot_indicators)
        
    def _determine_event_type(self, method: str, url: str, status_code: str) -> str:
        """Determine event type from web request"""
        url_lower = url.lower()
        
        if 'login' in url_lower or 'signin' in url_lower:
            return 'login'
        elif 'logout' in url_lower or 'signout' in url_lower:
            return 'logout'
        elif 'download' in url_lower or method == 'GET' and 'file' in url_lower:
            return 'file_access'
        elif method == 'POST' and int(status_code) == 200:
            return 'application_use'
        elif method == 'GET' and int(status_code) == 200:
            return 'page_view'
            
        return None
        
    def _extract_user_from_url(self, url: str) -> str:
        """Try to extract username from URL"""
        # Look for patterns like /user/john or /profile/jane
        user_patterns = [
            r'/user/(\w+)',
            r'/profile/(\w+)',
            r'/u/(\w+)',
            r'user=(\w+)'
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
                
        return 'unknown'
        
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse web log timestamp to ISO format"""
        try:
            # Format: 26/Dec/2023:14:30:45 +0000
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except:
            return datetime.now().isoformat()
