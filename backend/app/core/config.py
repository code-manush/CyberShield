from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberShield NIDPS"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    HOST: str = "127.0.0.1"
    PORT: int = 8000
    SECRET_KEY: str = "cybershield-secure-dev-key-change-in-production"

    DATABASE_URL: str = "sqlite:///./cybershield.db"

    # Prevention configuration
    PREVENTION_MODE: str = "OBSERVE"  # OBSERVE, ALERT, ENFORCE
    FIREWALL_ADAPTER: str = "SIMULATION"  # SIMULATION, LINUX_IPTABLES
    DEFAULT_BLOCK_DURATION_SECONDS: int = 300

    # Allowlist
    TRUSTED_IPS: str = "127.0.0.1,::1,10.0.0.1,192.168.1.1"

    # Detection parameters
    PORT_SCAN_THRESHOLD: int = 15
    PORT_SCAN_WINDOW_SECONDS: float = 10.0
    PORT_SCAN_COOLDOWN_SECONDS: float = 30.0

    SYN_FLOOD_THRESHOLD: int = 100
    SYN_FLOOD_WINDOW_SECONDS: float = 5.0
    SYN_FLOOD_COOLDOWN_SECONDS: float = 30.0

    BRUTE_FORCE_THRESHOLD: int = 10
    BRUTE_FORCE_WINDOW_SECONDS: float = 60.0
    BRUTE_FORCE_LOCKOUT_SECONDS: float = 60.0

    # Packet capture
    DEFAULT_INTERFACE: str = ""
    MAX_PACKET_QUEUE_SIZE: int = 10000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @property
    def trusted_ip_list(self) -> List[str]:
        return [ip.strip() for ip in self.TRUSTED_IPS.split(",") if ip.strip()]


settings = Settings()
