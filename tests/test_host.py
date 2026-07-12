"""Tests for the local host-audit module.

These test the pure classification logic (no real system calls), plus a
design-guarantee test: the audit is hard-wired to the local machine and cannot
be pointed at another host without rewriting the code.
"""

import inspect

from ajar import host


def test_localhost_is_not_exposed():
    assert host._is_exposed("127.0.0.1") is False
    assert host._is_exposed("127.0.0.53") is False
    assert host._is_exposed("::1") is False
    assert host._is_exposed("localhost") is False


def test_all_interfaces_is_exposed():
    assert host._is_exposed("0.0.0.0") is True
    assert host._is_exposed("::") is True
    assert host._is_exposed("*") is True


def test_specific_lan_ip_is_exposed():
    # a specific non-loopback IP is still reachable from the network
    assert host._is_exposed("192.168.1.20") is True


def test_proc_base_strips_extension():
    assert host._proc_base("node.exe") == "node"
    assert host._proc_base("python3") == "python3"
    assert host._proc_base("") == ""


def test_audit_is_local_only_by_design():
    # Design guarantee: audit_host takes NO target argument, so it can only ever
    # inspect the local machine. Turning it into a remote/port scanner would
    # require rewriting the code (and would be the modifier's responsibility).
    sig = inspect.signature(host.audit_host)
    assert list(sig.parameters) == [], "audit_host must accept no target host"


def test_known_db_ports_present():
    # sanity: the ports we warn about include the classic exposed databases
    for port in (5432, 3306, 27017, 6379):
        assert port in host._DB_PORTS
