from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ScanResult:
    """Resultado completo de escaneo de un puerto"""
    host: str
    port: int
    status: str
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    vulnerabilities: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    threat_info: Dict[str, Any] = field(default_factory=dict)
    os_guess: List[str] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    web_endpoints: List[str] = field(default_factory=list)

