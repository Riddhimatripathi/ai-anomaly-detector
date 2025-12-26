"""
Database Query Log Connector
Monitors MySQL/PostgreSQL query logs for suspicious database activity
"""
import re
import os
from datetime import datetime
from typing import Dict, Iterator
import mysql.connector
import psycopg2

from .base_connector import BaseConnector

class DatabaseConnector(BaseConnector):
    def __init__(self, config: Dict):
        super().__init__(config)
        self.db_type = config.get('db_type', 'mysql')  # mysql or postgresql
        self.log_files = config.get('log_files', [])
        self.db_config = config.get('database', {})
        self.last_positions = {}
        
    def connect(self) -> bool:
        """Connect to database and check log files"""
        try:
            # Test database connection if configured
            if self.db_config:
                if self.db_type == 'mysql':
                    conn = mysql.connector.connect(**self.db_config)
                    conn.close()
                elif self.db_type == 'postgresql':
                    conn = psycopg2.connect(**self.db_config)
                    conn.close()
                    
            # Check log files
            if self.log_files:
                accessible_files = []
                for log_file in self.log_files:
                    if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                        accessible_files.append(log_file)
                        self.last_positions[log_file] = self._get_file_size(log_file)
                        
                self.log_files = accessible_files
                
            return len(self.log_files) > 0 or bool(self.db_config)
            
        except Exception as e:
            print(f"Error connecting to database: {e}")
            return False
            
    def _get_file_size(self, file_path: str) -> int:
        """Get current file size"""
        try:
            return os.path.getsize(file_path)
        except:
            return 0
    
    def fetch_events(self) -> Iterator[str]:
        """Fetch database events from logs or queries"""
        # Read from log files
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
        """Parse database log entry"""
        try:
            if self.db_type == 'mysql':
                return self._parse_mysql_log(raw_event)
            elif self.db_type == 'postgresql':
                return self._parse_postgresql_log(raw_event)
                
        except Exception as e:
            print(f"Error parsing database log: {e}")
            
        return None
        
    def _parse_mysql_log(self, raw_event: str) -> Dict:
        """Parse MySQL general query log"""
        # MySQL log format: timestamp thread_id command_type query
        mysql_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}Z)\s+(\d+)\s+(\w+)\s+(.*)'
        
        match = re.match(mysql_pattern, raw_event)
        if not match:
            return None
            
        timestamp_str, thread_id, command_type, query = match.groups()
        
        # Analyze query for suspicious patterns
        query_lower = query.lower()
        event_type = 'database_query'
        suspicious_patterns = []
        
        if 'select' in query_lower and '*' in query_lower:
            suspicious_patterns.append('SELECT_ALL')
        if 'drop' in query_lower:
            suspicious_patterns.append('DROP_COMMAND')
        if 'delete' in query_lower and 'where' not in query_lower:
            suspicious_patterns.append('DELETE_WITHOUT_WHERE')
        if 'union' in query_lower:
            suspicious_patterns.append('SQL_INJECTION_ATTEMPT')
            
        return self.standardize_event({
            'timestamp': timestamp_str,
            'user_name': f'mysql_user_{thread_id}',
            'event_type': event_type,
            'action': command_type,
            'details': {
                'query': query,
                'thread_id': thread_id,
                'suspicious_patterns': suspicious_patterns,
                'raw': raw_event
            }
        })
        
    def _parse_postgresql_log(self, raw_event: str) -> Dict:
        """Parse PostgreSQL log"""
        # PostgreSQL log format varies, this is a basic parser
        pg_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3} \w+).*LOG:.*statement: (.*)'
        
        match = re.search(pg_pattern, raw_event)
        if not match:
            return None
            
        timestamp_str, query = match.groups()
        
        return self.standardize_event({
            'timestamp': self._parse_timestamp(timestamp_str),
            'user_name': 'postgresql_user',
            'event_type': 'database_query',
            'details': {
                'query': query,
                'raw': raw_event
            }
        })
        
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse database timestamp to ISO format"""
        try:
            # Try different timestamp formats
            for fmt in [
                "%Y-%m-%d %H:%M:%S.%f %Z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S"
            ]:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    return dt.isoformat()
                except:
                    continue
        except:
            pass
            
        return datetime.now().isoformat()
