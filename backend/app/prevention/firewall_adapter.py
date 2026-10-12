from abc import ABC, abstractmethod
import ipaddress
import subprocess
import platform
from typing import Tuple, Dict, Any, Optional
from datetime import datetime
from app.core.logging import logger


class BaseFirewallAdapter(ABC):
    """Abstract base class for defensive firewall adapters."""

    @abstractmethod
    def block_ip(self, ip_address: str, reason: str, duration_seconds: int) -> Tuple[bool, str, Dict[str, Any]]:
        """Block an IP address. Returns (success, message, metadata)."""
        pass

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Unblock an IP address. Returns (success, message, metadata)."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this firewall adapter is executable on current system."""
        pass


class SimulationFirewallAdapter(BaseFirewallAdapter):
    """Cross-platform safe simulation firewall adapter.
    
    Performs fully stateful, audited, simulated defensive actions without
    altering OS network routing or firewall state.
    """

    def __init__(self):
        self.simulated_blocks: Dict[str, Dict[str, Any]] = {}

    def is_available(self) -> bool:
        return True

    def block_ip(self, ip_address: str, reason: str, duration_seconds: int) -> Tuple[bool, str, Dict[str, Any]]:
        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return False, f"Invalid IP address format: {ip_address}", {}

        self.simulated_blocks[str(ip_obj)] = {
            "ip": str(ip_obj),
            "reason": reason,
            "blocked_at": datetime.utcnow().isoformat(),
            "duration": duration_seconds,
            "status": "SIMULATED_ACTIVE"
        }
        logger.info(f"[PREVENTION-SIMULATION] Simulated block applied to {ip_address} for {duration_seconds}s: {reason}")
        return True, f"Simulated block enacted for {ip_address}", {"mode": "SIMULATION", "duration": duration_seconds}

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str, Dict[str, Any]]:
        if ip_address in self.simulated_blocks:
            del self.simulated_blocks[ip_address]
            logger.info(f"[PREVENTION-SIMULATION] Simulated unblock applied to {ip_address}")
            return True, f"Simulated unblock applied for {ip_address}", {"mode": "SIMULATION"}
        return True, f"IP {ip_address} was not in active simulation blocks", {"mode": "SIMULATION"}


class LinuxIptablesAdapter(BaseFirewallAdapter):
    """Linux iptables adapter with strict validation and scoping."""

    def is_available(self) -> bool:
        if platform.system().lower() != "linux":
            return False
        try:
            res = subprocess.run(["which", "iptables"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return res.returncode == 0
        except Exception:
            return False

    def block_ip(self, ip_address: str, reason: str, duration_seconds: int) -> Tuple[bool, str, Dict[str, Any]]:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return False, f"Invalid IP address: {ip_address}", {}

        if not self.is_available():
            return False, "Linux iptables is not available on this host environment", {}

        clean_ip = str(ip_obj)
        cmd = ["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP", "-m", "comment", "--comment", "CyberShield-AutoBlock"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"[PREVENTION-IPTABLES] Blocked {clean_ip} via iptables")
            return True, f"iptables rule added for {clean_ip}", {"stdout": res.stdout}
        except subprocess.CalledProcessError as e:
            logger.error(f"[PREVENTION-IPTABLES] Failed to block {clean_ip}: {e.stderr}")
            return False, f"iptables command failed: {e.stderr.strip()}", {"error": str(e)}

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str, Dict[str, Any]]:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return False, f"Invalid IP address: {ip_address}", {}

        if not self.is_available():
            return False, "Linux iptables is not available on this host environment", {}

        clean_ip = str(ip_obj)
        cmd = ["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP", "-m", "comment", "--comment", "CyberShield-AutoBlock"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"[PREVENTION-IPTABLES] Unblocked {clean_ip} via iptables")
            return True, f"iptables rule removed for {clean_ip}", {"stdout": res.stdout}
        except subprocess.CalledProcessError as e:
            logger.error(f"[PREVENTION-IPTABLES] Failed to unblock {clean_ip}: {e.stderr}")
            return False, f"iptables unblock command failed: {e.stderr.strip()}", {"error": str(e)}
