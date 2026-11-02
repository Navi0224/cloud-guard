"""Firewall-rule helpers shared by the live EC2 check and the Terraform check.

Both scanners need to answer the same question - "does this ingress rule let
the whole internet reach an admin port?" - so the logic lives here once.
"""

from __future__ import annotations

from typing import Any

ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP"}
OPEN_IPV4 = "0.0.0.0/0"
OPEN_IPV6 = "::/0"

# CIS counts TCP, UDP and "all traffic". AWS accepts names or protocol numbers.
ALL_PROTOCOLS = {"-1", "all"}
PORT_PROTOCOLS = {"tcp", "6", "udp", "17"}


def covers_port(protocol: Any, from_port: Any, to_port: Any, port: int) -> bool:
    """True if a rule with this protocol and port range lets traffic reach `port`.

    * protocol "-1"/"all" means every protocol and every port.
    * otherwise the rule covers the inclusive range [from_port, to_port].
    * values we cannot interpret (e.g. an unresolved Terraform variable such as
      "${var.ssh_port}") return False - a known limitation of static analysis.
    """
    proto = str(protocol).strip().lower()
    if proto in ALL_PROTOCOLS:
        return True
    if proto not in PORT_PROTOCOLS:
        return False
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False
