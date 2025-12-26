"""
Generate fake user behavior data for testing
"""
import random
import json
from datetime import datetime, timedelta
from typing import List, Dict
import pandas as pd


class FakeDataGenerator:
    def __init__(self):
        self.users = [
            {"id": 1, "name": "Sarah Johnson", "role": "Accountant", "location": "New York"},
            {"id": 2, "name": "Mike Chen", "role": "Developer", "location": "California"},
            {"id": 3, "name": "Lisa Wilson", "role": "HR Manager", "location": "Texas"},
            {"id": 4, "name": "Bob Smith", "role": "Sales Rep", "location": "Florida"},
            {"id": 5, "name": "Anna Rodriguez", "role": "Marketing", "location": "Illinois"},
        ]
        
        self.normal_working_hours = (9, 17)  # 9 AM to 5 PM
        self.countries = ["United States", "Canada", "United Kingdom"]
        self.suspicious_countries = ["Russia", "China", "North Korea", "Unknown"]
        
        self.file_types = {
            "Accountant": ["financial_report.xlsx", "budget_2024.csv", "tax_documents.pdf"],
            "Developer": ["source_code.py", "database_schema.sql", "api_docs.md"],
            "HR Manager": ["employee_records.xlsx", "salary_data.csv", "contracts.pdf"],
            "Sales Rep": ["client_contacts.xlsx", "sales_report.pdf", "proposals.docx"],
            "Marketing": ["campaign_data.xlsx", "social_media.csv", "graphics.png"],
        }

    def generate_normal_behavior(self, days: int = 30):
        """Generate normal user behavior data"""
        events = []
        start_date = datetime.now() - timedelta(days=days)
        
        for day in range(days):
            current_date = start_date + timedelta(days=day)
            
            # Skip weekends for most activities
            if current_date.weekday() >= 5:  # Saturday=5, Sunday=6
                continue
                
            for user in self.users:
                # Generate normal login
                login_time = current_date.replace(
                    hour=random.randint(8, 10),
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59)
                )
                
                events.append({
                    "timestamp": login_time.isoformat(),
                    "user_id": user["id"],
                    "user_name": user["name"],
                    "event_type": "login",
                    "source_ip": f"192.168.1.{random.randint(1, 254)}",
                    "location": user["location"],
                    "country": "United States",
                    "device": f"LAPTOP-{user['id']}",
                    "success": True
                })
                
                # Generate file access during work hours
                num_file_accesses = random.randint(3, 8)
                for _ in range(num_file_accesses):
                    file_time = login_time + timedelta(
                        hours=random.randint(0, 8),
                        minutes=random.randint(0, 59)
                    )
                    
                    # Only access files relevant to their role
                    relevant_files = self.file_types.get(user["role"], ["generic_file.txt"])
                    
                    events.append({
                        "timestamp": file_time.isoformat(),
                        "user_id": user["id"],
                        "user_name": user["name"],
                        "event_type": "file_access",
                        "file_name": random.choice(relevant_files),
                        "file_size_mb": random.randint(1, 50),
                        "action": random.choice(["read", "read", "read", "edit"]),  # More reads than edits
                        "source_ip": f"192.168.1.{random.randint(1, 254)}",
                        "location": user["location"],
                        "country": "United States"
                    })
                
                # Generate logout
                logout_time = login_time + timedelta(hours=random.randint(7, 9))
                events.append({
                    "timestamp": logout_time.isoformat(),
                    "user_id": user["id"],
                    "user_name": user["name"],
                    "event_type": "logout",
                    "source_ip": f"192.168.1.{random.randint(1, 254)}",
                    "location": user["location"],
                    "country": "United States",
                    "device": f"LAPTOP-{user['id']}"
                })
        
        return events

    def generate_suspicious_behavior(self, num_events: int = 20):
        """Generate suspicious behavior that should trigger alerts"""
        events = []
        
        for _ in range(num_events):
            user = random.choice(self.users)
            event_type = random.choice([
                "suspicious_login", "mass_file_access", "unusual_time", 
                "foreign_location", "large_download"
            ])
            
            base_time = datetime.now() - timedelta(days=random.randint(0, 7))
            
            if event_type == "suspicious_login":
                # Login from suspicious country
                events.append({
                    "timestamp": base_time.isoformat(),
                    "user_id": user["id"],
                    "user_name": user["name"],
                    "event_type": "login",
                    "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "location": random.choice(["Moscow", "Beijing", "Pyongyang"]),
                    "country": random.choice(self.suspicious_countries),
                    "device": "Unknown Device",
                    "success": True,
                    "suspicious": True
                })
                
        return events

    def save_to_csv(self, events, filename: str):
        """Save events to CSV file"""
        df = pd.DataFrame(events)
        df.to_csv(filename, index=False)
        print(f"✅ Saved {len(events)} events to {filename}")

    def generate_dataset(self, output_file: str = "../data/user_behavior.csv"):
        """Generate complete dataset with normal and suspicious behavior"""
        print("🔄 Generating fake user behavior data...")
        
        # Generate normal behavior (90% of data)
        normal_events = self.generate_normal_behavior(days=30)
        print(f"📊 Generated {len(normal_events)} normal events")
        
        # Generate suspicious behavior (10% of data)
        suspicious_events = self.generate_suspicious_behavior(num_events=50)
        print(f"🚨 Generated {len(suspicious_events)} suspicious events")
        
        # Combine and shuffle
        all_events = normal_events + suspicious_events
        random.shuffle(all_events)
        
        # Save to file
        self.save_to_csv(all_events, output_file)
        
        return all_events


if __name__ == "__main__":
    generator = FakeDataGenerator()
    generator.generate_dataset()
