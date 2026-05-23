import re
import time
from typing import Dict, Any

from google.cloud import compute_v1

# GCP Project Configuration
PROJECT_ID = "test-project"
ZONE = "us-central1-a"


def is_valid_ip(ip: str) -> bool:
    pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return bool(pattern.match(ip))


def create_firewall_rule(
    ip_addr: str, port: int, limit_minutes: int = 60, notify_minutes: int = 0
) -> Dict[str, Any]:
    if not is_valid_ip(ip_addr):
        raise ValueError("Invalid IP address format")

    current_time = int(time.time() * 1000)
    expire_time = current_time + (limit_minutes * 60 * 1000)
    
    notify_time = 0
    if notify_minutes > 0 and notify_minutes < limit_minutes:
        notify_time = expire_time - (notify_minutes * 60 * 1000)
        
    rule_name = f"sentinel-rule-{current_time}"

    # Create the GCP Firewall Rule
    try:
        firewall_client = compute_v1.FirewallsClient()
        firewall_resource = compute_v1.Firewall(
            name=rule_name,
            direction="INGRESS",
            source_ranges=[f"{ip_addr}/32"],
            allowed=[compute_v1.Allowed(I_p_protocol="tcp", ports=[str(port)])],
            network="global/networks/default",
        )
        # Insert
        firewall_client.insert(
            project=PROJECT_ID, firewall_resource=firewall_resource
        )
    except Exception as e:
        raise RuntimeError(f"GCP API Error: {str(e)}")

    return {
        "ruleName": rule_name,
        "ipAddr": ip_addr,
        "port": port,
        "status": "open",
        "createdAt": current_time,
        "expireAt": expire_time,
        "notifyAt": notify_time,
    }


def find_firewall_rule_by_port(port: int) -> str | None:
    """
    GCP API를 조회하여 해당 포트가 열려있는 방화벽 규칙의 이름을 반환합니다.
    없으면 None을 반환합니다.
    """
    try:
        firewall_client = compute_v1.FirewallsClient()
        request = compute_v1.ListFirewallsRequest(project=PROJECT_ID)
        
        for fw in firewall_client.list(request=request):
            if not fw.name.startswith("sentinel-rule-"):
                continue
            for allowed in fw.allowed:
                if allowed.I_p_protocol.lower() == "tcp" and str(port) in allowed.ports:
                    return fw.name
        return None
    except Exception as e:
        print(f"GCP Firewall List API Error: {e}")
        return None


def delete_firewall_rule(rule_name: str):
    try:
        firewall_client = compute_v1.FirewallsClient()
        firewall_client.delete(project=PROJECT_ID, firewall=rule_name)
    except Exception as e:
        raise RuntimeError(f"GCP API Error: {str(e)}")

