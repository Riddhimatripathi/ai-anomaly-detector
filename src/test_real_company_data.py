"""
Generate realistic company data for testing
"""
import pandas as pd
from datetime import datetime, timedelta
import random

# Simulate a real company with 20 employees
employees = [
    {"id": i, "name": f"Employee_{i}", "role": random.choice(["Engineer", "Manager", "Analyst", "Admin"]), 
     "location": random.choice(["Office_NY", "Office_SF", "Office_LA", "Remote"])}
    for i in range(1, 21)
]

events = []
start_date = datetime.now() - timedelta(days=7)

# Generate a week of normal activity
for day in range(7):
    current_date = start_date + timedelta(days=day)
    
    # Skip weekends
    if current_date.weekday() >= 5:
        continue
    
    for emp in employees:
        # Normal working hours: 9 AM to 5 PM
        login_time = current_date.replace(hour=random.randint(8, 10), minute=random.randint(0, 59))
        
        # Login event
        events.append({
            'timestamp': login_time.isoformat(),
            'user_id': emp['id'],
            'user_name': emp['name'],
            'event_type': 'login',
            'source_ip': f"192.168.1.{random.randint(1, 254)}",
            'location': emp['location'],
            'country': 'United States',
            'device': f"DEVICE-{emp['id']}",
            'success': True
        })
        
        # Some file access during the day
        for _ in range(random.randint(5, 15)):
            file_time = login_time + timedelta(hours=random.randint(0, 8), minutes=random.randint(0, 59))
            events.append({
                'timestamp': file_time.isoformat(),
                'user_id': emp['id'],
                'user_name': emp['name'],
                'event_type': 'file_access',
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'location': emp['location'],
                'country': 'United States',
                'file_name': f"document_{random.randint(1, 100)}.pdf",
                'file_size_mb': random.randint(1, 50),
                'action': random.choice(['read', 'edit', 'download'])
            })
        
        # Logout
        logout_time = login_time + timedelta(hours=random.randint(7, 9))
        events.append({
            'timestamp': logout_time.isoformat(),
            'user_id': emp['id'],
            'user_name': emp['name'],
            'event_type': 'logout',
            'source_ip': f"192.168.1.{random.randint(1, 254)}",
            'location': emp['location'],
            'country': 'United States',
            'device': f"DEVICE-{emp['id']}",
            'success': True
        })

# Add some suspicious activities
# 1. After-hours access
suspicious_emp = random.choice(employees)
suspicious_time = (datetime.now() - timedelta(days=2)).replace(hour=2, minute=30)
events.append({
    'timestamp': suspicious_time.isoformat(),
    'user_id': suspicious_emp['id'],
    'user_name': suspicious_emp['name'],
    'event_type': 'login',
    'source_ip': '203.0.113.45',
    'location': 'Moscow',
    'country': 'Russia',
    'device': 'Unknown',
    'success': True
})

# 2. Mass data download
for _ in range(20):
    download_time = suspicious_time + timedelta(minutes=random.randint(1, 30))
    events.append({
        'timestamp': download_time.isoformat(),
        'user_id': suspicious_emp['id'],
        'user_name': suspicious_emp['name'],
        'event_type': 'file_access',
        'source_ip': '203.0.113.45',
        'location': 'Moscow',
        'country': 'Russia',
        'file_name': f"confidential_data_{random.randint(1, 100)}.xlsx",
        'file_size_mb': random.randint(100, 500),
        'action': 'download'
    })

# Save to CSV
df = pd.DataFrame(events)
df = df.sort_values('timestamp')
df.to_csv('data/real_company_test_data.csv', index=False)

print(f"✅ Created realistic company data: {len(events)} events")
print(f"📊 {len(employees)} employees, 7 days of activity")
print(f"🚨 Includes suspicious after-hours access and mass downloads")
print(f"📁 Saved to: data/real_company_test_data.csv")
