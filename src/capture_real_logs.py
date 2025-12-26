import pandas as pd
import subprocess
from datetime import datetime
import re

def parse_auth_log():
    """Parse real authentication logs"""
    events = []
    
    try:
        # Read auth log (real login attempts on your system)
        result = subprocess.run(['sudo', 'cat', '/var/log/auth.log'], 
                              capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if 'sshd' in line or 'sudo' in line or 'su:' in line:
                # Parse timestamp
                parts = line.split()
                if len(parts) > 5:
                    timestamp = datetime.now().isoformat()
                    
                    # Extract user
                    user_match = re.search(r'user=(\w+)', line)
                    user = user_match.group(1) if user_match else 'unknown'
                    
                    # Extract IP if available
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    ip = ip_match.group(1) if ip_match else '127.0.0.1'
                    
                    # Determine event type
                    if 'Failed password' in line:
                        event_type = 'failed_login'
                        success = False
                    elif 'Accepted' in line:
                        event_type = 'login'
                        success = True
                    elif 'sudo' in line:
                        event_type = 'sudo_command'
                        success = True
                    else:
                        continue
                    
                    events.append({
                        'timestamp': timestamp,
                        'user_name': user,
                        'event_type': event_type,
                        'source_ip': ip,
                        'location': 'Local',
                        'country': 'Local',
                        'device': 'System',
                        'success': success
                    })
    except Exception as e:
        print(f"Error reading logs: {e}")
    
    return events

# Capture real events
print("🔍 Capturing REAL system events...")
events = parse_auth_log()

if events:
    df = pd.DataFrame(events)
    output_file = f'../data/incoming/real_system_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    df.to_csv(output_file, index=False)
    print(f"✅ Captured {len(events)} REAL events")
    print(f"📁 Saved to: {output_file}")
else:
    print("❌ No events captured. Try generating some activity first.")

