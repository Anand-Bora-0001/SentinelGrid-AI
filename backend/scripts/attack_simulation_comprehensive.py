#!/usr/bin/env python3
"""
Comprehensive Attack Simulation Suite
Monitors ALL types of attacks: ThreatSensor services + Demo E-commerce + Web applications
"""

import requests
import time
import random
import os
import sqlite3
from datetime import datetime, timezone
import json

# Configuration
DEMO_ECOMMERCE_URL = "http://localhost:5000"
SENTINELGRID_API_URL = "http://localhost:8000"
DASHBOARD_URL = "http://localhost:5173"
ATTACK_DELAY = 0.3

def print_banner():
    """Print comprehensive banner"""
    print("\n" + "="*70)
    print("🎯 SentinelGrid COMPREHENSIVE Attack Monitoring Suite")
    print("   Monitors ALL attack types: ThreatSensors + Web Apps + E-commerce")
    print("="*70)
    print(f"Target Demo App: {DEMO_ECOMMERCE_URL}")
    print(f"SentinelGrid API: {SENTINELGRID_API_URL}")
    print(f"Dashboard: {DASHBOARD_URL}/dashboard.html")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70 + "\n")

def clear_database():
    """Clear the SentinelGrid database for fresh start"""
    print("🗑️  Clearing SentinelGrid database...")
    
    db_paths = [
        "backend/sentinelgrid.db",
        "sentinelgrid.db"
    ]
    
    for db_path in db_paths:
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM events")
                conn.commit()
                conn.close()
                print(f"   ✅ Cleared {db_path}")
            except Exception as e:
                print(f"   ⚠️ Could not clear {db_path}: {e}")
    
    print("   🔄 Database reset complete\n")

def login_to_sentinelgrid():
    """Login to SentinelGrid and get token"""
    print("🔐 Authenticating with SentinelGrid...")
    
    try:
        response = requests.post(
            f"{SENTINELGRID_API_URL}/auth/login",
            data={"username": "admin", "password": "admin123"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        
        if response.status_code == 200:
            token = response.json()["access_token"]
            print("   ✅ Authentication successful")
            return token
        else:
            print(f"   ❌ Authentication failed: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"   ❌ Authentication error: {e}")
        return None

def simulate_ssh_threat_sensor_attacks():
    """Simulate SSH threat_sensor attacks"""
    print("🔐 Simulating SSH ThreatSensor Attacks...")
    
    ssh_attacks = [
        {"username": "root", "password": "123456", "severity": "CRITICAL", "command": "rm -rf /"},
        {"username": "admin", "password": "admin", "severity": "HIGH", "command": "cat /etc/shadow"},
        {"username": "root", "password": "password", "severity": "CRITICAL", "command": "sudo su"},
        {"username": "user", "password": "user", "severity": "MEDIUM", "command": "ls -la"},
        {"username": "guest", "password": "guest", "severity": "LOW", "command": "whoami"},
        {"username": "oracle", "password": "oracle", "severity": "MEDIUM", "command": "netstat -tulpn"},
    ]
    
    for i, attack in enumerate(ssh_attacks):
        attack_data = {
            "service": "SSH",
            "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 22,
            "username": attack["username"],
            "password": attack["password"],
            "command": attack["command"],
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "brute_force",
            "session_id": f"ssh_{random.randint(1000, 9999)}",
            "user_agent": "OpenSSH_7.4",
            "endpoint": "/ssh",
            "method": "SSH_AUTH",
            "payload": f"{attack['username']}:{attack['password']}"
        }
        
        send_attack_to_sentinelgrid(attack_data, f"SSH Attack {i+1}")
        time.sleep(ATTACK_DELAY)

def simulate_ftp_threat_sensor_attacks():
    """Simulate FTP threat_sensor attacks"""
    print("\n📁 Simulating FTP ThreatSensor Attacks...")
    
    ftp_attacks = [
        {"username": "anonymous", "password": "guest@example.com", "severity": "MEDIUM", "command": "LIST"},
        {"username": "ftp", "password": "ftp", "severity": "MEDIUM", "command": "RETR /etc/passwd"},
        {"username": "admin", "password": "admin", "severity": "HIGH", "command": "STOR malware.exe"},
        {"username": "root", "password": "123456", "severity": "CRITICAL", "command": "CWD /root"},
        {"username": "user", "password": "password", "severity": "MEDIUM", "command": "DELE important.txt"},
    ]
    
    for i, attack in enumerate(ftp_attacks):
        attack_data = {
            "service": "FTP",
            "source_ip": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 21,
            "username": attack["username"],
            "password": attack["password"],
            "command": attack["command"],
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "credential_stuffing",
            "session_id": f"ftp_{random.randint(1000, 9999)}",
            "user_agent": "FileZilla/3.46.0",
            "endpoint": "/ftp",
            "method": "FTP_AUTH",
            "payload": f"{attack['username']}:{attack['password']}"
        }
        
        send_attack_to_sentinelgrid(attack_data, f"FTP Attack {i+1}")
        time.sleep(ATTACK_DELAY)

def simulate_http_threat_sensor_attacks():
    """Simulate HTTP threat_sensor attacks"""
    print("\n🌐 Simulating HTTP ThreatSensor Attacks...")
    
    http_attacks = [
        {"endpoint": "/admin", "method": "GET", "severity": "HIGH"},
        {"endpoint": "/wp-admin", "method": "POST", "severity": "HIGH"},
        {"endpoint": "/phpmyadmin", "method": "GET", "severity": "CRITICAL"},
        {"endpoint": "/.env", "method": "GET", "severity": "MEDIUM"},
        {"endpoint": "/config.php", "method": "GET", "severity": "MEDIUM"},
        {"endpoint": "/login.php", "method": "POST", "severity": "MEDIUM"},
        {"endpoint": "/backup.sql", "method": "GET", "severity": "HIGH"},
        {"endpoint": "/wp-config.php", "method": "GET", "severity": "HIGH"},
    ]
    
    for i, attack in enumerate(http_attacks):
        attack_data = {
            "service": "HTTP",
            "source_ip": f"172.16.{random.randint(1,254)}.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "username": random.choice(["admin", "root", "user", None]),
            "password": random.choice(["admin123", "password", "123456", None]),
            "command": f"{attack['method']} {attack['endpoint']}",
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "web_probe",
            "session_id": f"http_{random.randint(1000, 9999)}",
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "curl/7.68.0",
                "python-requests/2.25.1",
                "Nmap NSE"
            ]),
            "endpoint": attack["endpoint"],
            "method": attack["method"],
            "payload": f"{attack['method']} {attack['endpoint']}"
        }
        
        send_attack_to_sentinelgrid(attack_data, f"HTTP Attack {i+1}")
        time.sleep(ATTACK_DELAY)

def simulate_telnet_threat_sensor_attacks():
    """Simulate TELNET threat_sensor attacks"""
    print("\n📟 Simulating TELNET ThreatSensor Attacks...")
    
    telnet_attacks = [
        {"username": "admin", "password": "admin", "severity": "HIGH", "command": "enable"},
        {"username": "root", "password": "root", "severity": "CRITICAL", "command": "show config"},
        {"username": "cisco", "password": "cisco", "severity": "HIGH", "command": "copy running-config"},
        {"username": "admin", "password": "password", "severity": "HIGH", "command": "reload"},
    ]
    
    for i, attack in enumerate(telnet_attacks):
        attack_data = {
            "service": "TELNET",
            "source_ip": f"203.0.113.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 23,
            "username": attack["username"],
            "password": attack["password"],
            "command": attack["command"],
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "brute_force",
            "session_id": f"telnet_{random.randint(1000, 9999)}",
            "user_agent": "Telnet Client",
            "endpoint": "/telnet",
            "method": "TELNET_AUTH",
            "payload": f"{attack['username']}:{attack['password']}"
        }
        
        send_attack_to_sentinelgrid(attack_data, f"TELNET Attack {i+1}")
        time.sleep(ATTACK_DELAY)

def simulate_demo_ecommerce_attacks():
    """Simulate attacks against demo e-commerce application"""
    print("\n🛒 Simulating Demo E-commerce Attacks...")
    
    # Brute force login attacks
    print("   🔓 Brute force login attempts...")
    common_passwords = [
        "admin", "password", "123456", "admin123", "root",
        "password123", "qwerty", "letmein", "welcome", "monkey"
    ]
    
    usernames = ["admin", "administrator", "root", "user", "guest"]
    
    for i in range(6):
        username = random.choice(usernames)
        password = random.choice(common_passwords)
        
        # Send to demo app
        try:
            response = requests.post(
                f"{DEMO_ECOMMERCE_URL}/login",
                data={"email": f"{username}@example.com", "password": password},
                timeout=3
            )
            
            # Also send to SentinelGrid for monitoring
            attack_data = {
                "service": "DEMO_ECOMMERCE",
                "source_ip": f"127.0.0.1",
                "source_port": random.randint(1024, 65535),
                "destination_port": 5000,
                "username": f"{username}@example.com",
                "password": password,
                "command": f"POST /login",
                "severity": "HIGH" if username in ["admin", "root"] else "MEDIUM",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "brute_force",
                "session_id": f"ecom_{random.randint(1000, 9999)}",
                "user_agent": "Mozilla/5.0 (Attack Bot)",
                "endpoint": "/login",
                "method": "POST",
                "payload": f"{username}@example.com:{password}"
            }
            
            send_attack_to_sentinelgrid(attack_data, f"E-commerce Login Attack {i+1}")
            
        except Exception as e:
            print(f"   ⚠️ E-commerce attack {i+1}: {e}")
        
        time.sleep(ATTACK_DELAY)

def simulate_sql_injection_attacks():
    """Simulate SQL injection attempts"""
    print("\n💉 Simulating SQL Injection Attacks...")
    
    sql_payloads = [
        {"payload": "' OR '1'='1", "severity": "CRITICAL"},
        {"payload": "'; DROP TABLE users; --", "severity": "CRITICAL"},
        {"payload": "' UNION SELECT * FROM users --", "severity": "HIGH"},
        {"payload": "admin'--", "severity": "HIGH"},
        {"payload": "' OR 1=1 --", "severity": "HIGH"}
    ]
    
    for i, attack in enumerate(sql_payloads):
        # Try against demo e-commerce
        try:
            response = requests.post(
                f"{DEMO_ECOMMERCE_URL}/login",
                data={"email": attack["payload"], "password": "test"},
                timeout=3
            )
        except:
            pass
        
        # Send to SentinelGrid
        attack_data = {
            "service": "WEB_APP",
            "source_ip": f"198.51.100.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "username": attack["payload"],
            "password": "test",
            "command": f"SQL Injection: {attack['payload'][:30]}...",
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "sql_injection",
            "session_id": f"sql_{random.randint(1000, 9999)}",
            "user_agent": "sqlmap/1.4.7",
            "endpoint": "/login",
            "method": "POST",
            "payload": attack["payload"]
        }
        
        send_attack_to_sentinelgrid(attack_data, f"SQL Injection {i+1}")
        time.sleep(ATTACK_DELAY)

def simulate_directory_traversal_attacks():
    """Simulate directory traversal attacks"""
    print("\n📁 Simulating Directory Traversal Attacks...")
    
    traversal_payloads = [
        {"payload": "../../../etc/passwd", "severity": "HIGH"},
        {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "severity": "HIGH"},
        {"payload": "....//....//....//etc/passwd", "severity": "MEDIUM"},
        {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "severity": "MEDIUM"}
    ]
    
    for i, attack in enumerate(traversal_payloads):
        # Try against demo e-commerce
        try:
            response = requests.get(f"{DEMO_ECOMMERCE_URL}/products?file={attack['payload']}", timeout=3)
        except:
            pass
        
        # Send to SentinelGrid
        attack_data = {
            "service": "WEB_APP",
            "source_ip": f"203.0.113.{random.randint(1,254)}",
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "username": None,
            "password": None,
            "command": f"Directory Traversal: {attack['payload'][:30]}...",
            "severity": attack["severity"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "directory_traversal",
            "session_id": f"dir_{random.randint(1000, 9999)}",
            "user_agent": "DirBuster-1.0",
            "endpoint": f"/products?file={attack['payload']}",
            "method": "GET",
            "payload": attack["payload"]
        }
        
        send_attack_to_sentinelgrid(attack_data, f"Directory Traversal {i+1}")
        time.sleep(ATTACK_DELAY)

def send_attack_to_sentinelgrid(attack_data, attack_name):
    """Send attack data to SentinelGrid"""
    try:
        response = requests.post(
            f"{SENTINELGRID_API_URL}/api/ingest",
            json=attack_data,
            timeout=5
        )
        
        if response.status_code == 200:
            print(f"   ✅ {attack_name}: {attack_data['service']} from {attack_data['source_ip']} -> {attack_data['severity']}")
        else:
            print(f"   ❌ {attack_name}: Failed ({response.status_code})")
            
    except Exception as e:
        print(f"   ⚠️ {attack_name}: {str(e)[:50]}...")

def check_comprehensive_results(token):
    """Check all attack results in SentinelGrid"""
    print("\n📊 Checking Comprehensive Attack Results...")
    
    if not token:
        print("   ❌ No authentication token available")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Get stats
        stats_response = requests.get(f"{SENTINELGRID_API_URL}/api/stats", headers=headers, timeout=5)
        events_response = requests.get(f"{SENTINELGRID_API_URL}/api/events?limit=50", headers=headers, timeout=5)
        
        if stats_response.status_code == 200 and events_response.status_code == 200:
            stats = stats_response.json()
            events = events_response.json()
            
            print(f"   ✅ Total Events: {stats.get('total_events', 0)}")
            print(f"   ✅ Recent Events: {len(events)}")
            
            # Count by service
            service_counts = {}
            severity_counts = {}
            attack_type_counts = {}
            
            for event in events:
                service = event.get('service', 'Unknown')
                severity = event.get('severity', 'Unknown')
                attack_type = event.get('attack_type', 'Unknown')
                
                service_counts[service] = service_counts.get(service, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            
            print(f"   📊 By Service: {dict(service_counts)}")
            print(f"   📊 By Severity: {dict(severity_counts)}")
            print(f"   📊 By Attack Type: {dict(attack_type_counts)}")
            
        else:
            print(f"   ❌ Failed to fetch results: Stats {stats_response.status_code}, Events {events_response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Error checking results: {e}")

def main():
    """Run comprehensive attack simulation"""
    print_banner()
    
    # Option to reset database
    reset_choice = input("🔄 Reset database before starting? (y/N): ").lower().strip()
    if reset_choice == 'y':
        clear_database()
    
    # Login to SentinelGrid
    token = login_to_sentinelgrid()
    
    # Run ALL attack simulations
    simulate_ssh_threat_sensor_attacks()
    simulate_ftp_threat_sensor_attacks()
    simulate_http_threat_sensor_attacks()
    simulate_telnet_threat_sensor_attacks()
    simulate_demo_ecommerce_attacks()
    simulate_sql_injection_attacks()
    simulate_directory_traversal_attacks()
    
    # Check comprehensive results
    check_comprehensive_results(token)
    
    # Final instructions
    print("\n" + "="*70)
    print("🎉 COMPREHENSIVE Attack Simulation Complete!")
    print("="*70)
    print("📊 View ALL attack types at:")
    print(f"   → Dashboard: {DASHBOARD_URL}/dashboard.html")
    print("   → Login: admin / admin123")
    print()
    print("🔄 You should now see attacks from:")
    print("   → SSH ThreatSensor (brute force, command injection)")
    print("   → FTP ThreatSensor (credential stuffing, file access)")
    print("   → HTTP ThreatSensor (web probes, admin access)")
    print("   → TELNET ThreatSensor (network device attacks)")
    print("   → Demo E-commerce (login attacks)")
    print("   → Web Applications (SQL injection, directory traversal)")
    print("="*70)

if __name__ == "__main__":
    main()