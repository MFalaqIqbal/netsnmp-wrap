from dataclasses import dataclass
from typing import Optional
from ipaddress import ip_address
from exceptions import *


@dataclass
class SNMPv3:
    user: str
    auth: Optional[str] = None
    encrypt: Optional[str] = None
    encrypt_type: Optional[str] = None
    auth_type: Optional[str] = None

    def __post_init__(self):
        if self.auth_type is not None:
            if self.auth_type.lower() not in ["sha", "sha256", "sha512"]:
                raise ValueError(f'Unsupported Authentication Type -> {self.auth_type}')
            else:
                self.auth_type = self.auth_type.lower()
        if self.encrypt_type is not None:
            if self.encrypt_type.lower() not in ["md5", "aes128", "aes256", "aes512"]:
                raise ValueError(f'Unsupported Encryption Type -> {self.encrypt_type}')
            else:
                self.encrypt_type = self.encrypt_type.lower()


@dataclass
class SNMPv2:
    community: str

    def __post_init__(self):
        if not isinstance(self.community, str):
            raise ValueError(f'Community must be string -> {self.community}')


def validate_ip(ip):
    try:
        _ip = ip_address(ip)
        if not _ip.is_private:
            raise InvalidIPAddress(ip, "Private")
        else:
            return str(_ip), _ip.version
    except ValueError:
        raise InvalidIPAddress(ip)


def valid_snmp_output(cmd_out):
    if "No Response from" in cmd_out:
        raise SNMPTimedOut()
    return
