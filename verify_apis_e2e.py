import urllib.request
import urllib.parse
import json
import time

BASE_URL = "http://localhost:8000"

def make_request(path, method="GET", headers=None, data=None, is_json=True):
    url = f"{BASE_URL}{path}"
    req_headers = {}
    if is_json:
        req_headers["Content-Type"] = "application/json"
    else:
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        
    if headers:
        req_headers.update(headers)
        
    req_data = None
    if data is not None:
        if is_json:
            req_data = json.dumps(data).encode("utf-8")
        else:
            req_data = urllib.parse.urlencode(data).encode("utf-8")
            
    req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            res_data = response.read().decode("utf-8")
            return json.loads(res_data), response.status
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return json.loads(err_msg), e.code
        except Exception:
            return {"error": err_msg}, e.code
    except Exception as e:
        return {"error": str(e)}, 500

def test_flow():
    print("=== STARTING SENTINELGRID AI INTEGRATION & STABILIZATION VERIFICATION ===\n")
    
    # 1. Health Check
    print("1. Checking Service Health...")
    health_res, health_code = make_request("/health")
    print(f"Health Check status: {health_code}")
    print(json.dumps(health_res, indent=2))
    print("-" * 50)
    
    # 2. Login
    print("2. Authenticating as admin...")
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    login_res, login_code = make_request("/auth/login", method="POST", data=login_data, is_json=False)
    if login_code != 200:
        print(f"Login failed: {login_code}, {login_res}")
        return
        
    token = login_res["access_token"]
    auth_headers = {
        "Authorization": f"Bearer {token}"
    }
    print("Authentication successful!")
    print("-" * 50)
    
    # 3. MITRE ATT&CK Matrix
    print("3. Fetching MITRE ATT&CK Matrix...")
    matrix_res, matrix_code = make_request("/api/mitre/matrix", headers=auth_headers)
    print(f"MITRE Matrix status: {matrix_code}")
    print(f"Total tactics: {len(matrix_res.get('techniques_by_tactic', {}))}")
    print(f"Total detections: {matrix_res.get('total_detections', 0)}")
    print("-" * 50)
    
    # 4. Predictions / Next Actions
    print("4. Fetching Attacker Next Action Predictions...")
    pred_res, pred_code = make_request("/api/predictions/next-actions", headers=auth_headers)
    print(f"Predictions status: {pred_code}")
    print(json.dumps(pred_res, indent=2))
    print("-" * 50)
    
    # 5. Digital Twin / Asset Topology
    print("5. Fetching Digital Twin Topology...")
    topo_res, topo_code = make_request("/api/assets/topology", headers=auth_headers)
    print(f"Topology status: {topo_code}")
    print(f"Nodes in topology: {len(topo_res.get('nodes', []))}")
    print(f"Edges in topology: {len(topo_res.get('edges', []))}")
    print("-" * 50)
    
    # 6. Anomaly Detection (UEBA) Analysis of mock incident payload
    print("6. Ingesting & Analyzing Mock Incident Event (UEBA Analysis)...")
    mock_payload = {
        "organization_id": 1,
        "entity_id": "admin",
        "entity_type": "user",
        "location": "Russia",
        "failed_logins": 15,
        "privilege_escalation": True
    }
    anomaly_res, anomaly_code = make_request("/api/v1/anomaly/analyze", method="POST", headers=auth_headers, data=mock_payload)
    print(f"Anomaly analysis status: {anomaly_code}")
    print(json.dumps(anomaly_res, indent=2))
    print("-" * 50)
    
    # 7. Threat Intelligence (RAG Engine)
    print("7. Querying Threat Intelligence RAG Engine...")
    rag_query = {
        "question": "What is CVE-2023-23397 Outlook Elevation of Privilege Vulnerability?"
    }
    rag_res, rag_code = make_request("/api/threat-intel/ask", method="POST", headers=auth_headers, data=rag_query)
    print(f"Threat Intel RAG status: {rag_code}")
    print(json.dumps(rag_res, indent=2))
    print("-" * 50)
    
    # 8. Incident Creation & Response Orchestrator
    print("8. Creating High-Severity Incident to test Response Orchestrator...")
    incident_payload = {
        "title": "Critical Infrastructure Ransomware Attack Simulation",
        "description": "Anomalous behavior on SCADA network indicating ransomware deployment. User admin logging in from Russia.",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1078", "T1068"],
        "affected_assets": [1]
    }
    inc_res, inc_code = make_request("/api/incidents", method="POST", headers=auth_headers, data=incident_payload)
    print(f"Incident creation status: {inc_code}")
    print(json.dumps(inc_res, indent=2))
    
    inc_id = inc_res["id"]
    print(f"\nGenerating Response Playbook Actions for Incident #{inc_id}...")
    resp_res, resp_code = make_request(f"/api/incidents/{inc_id}/response", method="POST", headers=auth_headers)
    print(f"Response actions status: {resp_code}")
    print(json.dumps(resp_res, indent=2))
    
    # 9. List and Approve Actions
    print("\n9. Listing proposed response actions...")
    actions_res, actions_code = make_request(f"/api/response/actions?incident_id={inc_id}", headers=auth_headers)
    print(f"List response actions status: {actions_code}")
    print(f"Found {len(actions_res)} proposed actions.")
    for action in actions_res:
        print(f"Proposed: ID={action['id']}, Type={action['action_type']}, Target={action['target']}, Confidence={action['confidence']}, Status={action['status']}")
        
    if actions_res:
        action_id = actions_res[0]["id"]
        print(f"\nApproving proposed action ID={action_id} to simulate firewall blocking...")
        approve_res, approve_code = make_request(f"/api/response/actions/{action_id}/approve", method="POST", headers=auth_headers)
        print(f"Approval simulation status: {approve_code}")
        print(json.dumps(approve_res, indent=2))
        
    print("\n=== INTEGRATION & STABILIZATION VERIFICATION COMPLETED ===")

if __name__ == "__main__":
    test_flow()
