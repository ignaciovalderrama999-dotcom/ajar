"""Host / local-environment security audit.

Inspects the *local* machine's own attack surface — which ports are listening,
which process owns each, whether a service is bound to localhost or to every
network interface, and the firewall state — then reports risky exposure.

Strictly defensive and read-only: it only reads the state of THIS machine, never
scans another host, never opens a connection, and never changes anything. It
reports and recommends; you decide. It is not an antivirus and does not look for
malware.

Requires the optional ``psutil`` dependency (``pip install ajar-scanner[host]``).
"""

from __future__ import annotations

import platform
import subprocess

from .models import Finding, Rule, Severity

# Database ports: a DB reachable from the network (0.0.0.0) is a classic serious
# exposure — often with a default or no password.
_DB_PORTS: dict[int, str] = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    1433: "SQL Server",
    5984: "CouchDB",
    11211: "Memcached",
    9042: "Cassandra",
    8086: "InfluxDB",
    5601: "Kibana",
}

# Ports and process names that indicate a local development server.
_DEV_PORTS: dict[int, str] = {
    3000: "Node/Next.js dev server",
    3001: "Node dev server",
    5173: "Vite dev server",
    5174: "Vite dev server",
    4200: "Angular dev server",
    4321: "Astro dev server",
    8000: "Django/HTTP dev server",
    5000: "Flask dev server",
    8080: "HTTP dev server",
}
_DEV_PROCS = {"node", "python", "python3", "deno", "bun", "php", "ruby", "vite"}


def psutil_available() -> bool:
    try:
        import psutil  # noqa: F401

        return True
    except Exception:
        return False


def _proc_base(name: str) -> str:
    return name.rsplit(".", 1)[0].lower() if name else ""


def _is_exposed(ip: str) -> bool:
    """True if the socket listens on all interfaces (reachable from the network)."""
    if ip in ("0.0.0.0", "::", "*"):
        return True
    if ip.startswith("127.") or ip in ("::1", "localhost"):
        return False
    # a specific non-loopback IP is also network-reachable
    return True


def _rule(rid: str, name: str, sev: Severity, msg: str, why: str, fix: str, refs=()):
    return Rule(
        id=rid, name=name, severity=sev, category="host",
        message=msg, pattern="", why=why, fix=fix, references=tuple(refs),
        context="any",
    )


def _listening_sockets():
    """Yield (ip, port, pid, process_name) for every LISTENing TCP socket."""
    import psutil

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        ip, port = conn.laddr
        proc = ""
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid).name()
            except Exception:
                proc = "?"
        yield ip, port, conn.pid, proc


def _firewall_findings() -> list[Finding]:
    """Report disabled firewall profiles (Windows/Linux, best effort)."""
    system = platform.system()
    findings: list[Finding] = []
    try:
        if system == "Windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines():
                if "=" not in line:
                    continue
                name, _, enabled = line.partition("=")
                if enabled.strip().lower() in ("false", "0"):
                    findings.append(Finding(
                        rule=_rule(
                            "HOST_FIREWALL_DISABLED", "Firewall profile disabled",
                            Severity.MEDIUM,
                            f"The Windows Firewall '{name.strip()}' profile is turned off.",
                            "With the firewall off, any service listening on your machine is "
                            "reachable from the local network with no filtering.",
                            f"Re-enable it: Windows Security -> Firewall & network protection -> "
                            f"turn on the {name.strip()} network firewall.",
                            ["https://owasp.org/www-community/controls/Network_Segmentation"],
                        ),
                        path=f"firewall/{name.strip().lower()}", line=0, column=0,
                        evidence=f"{name.strip()} profile: disabled",
                    ))
        elif system == "Linux":
            out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10).stdout
            if "inactive" in out.lower():
                findings.append(Finding(
                    rule=_rule(
                        "HOST_FIREWALL_DISABLED", "Firewall inactive", Severity.MEDIUM,
                        "The ufw firewall is inactive.",
                        "No packet filtering means exposed services are reachable unfiltered.",
                        "Enable it: sudo ufw enable (after allowing the ports you need).",
                    ),
                    path="firewall/ufw", line=0, column=0, evidence="ufw: inactive",
                ))
    except Exception:
        pass  # firewall check is best-effort; never fail the whole audit over it
    return findings


def audit_host() -> list[Finding]:
    """Audit the local machine's attack surface. Returns findings."""
    if not psutil_available():
        raise RuntimeError(
            "host audit needs psutil — install it with:  pip install 'ajar-scanner[host]'"
        )

    findings: list[Finding] = []
    for ip, port, pid, proc in _listening_sockets():
        exposed = _is_exposed(ip)
        base = _proc_base(proc)
        where = f"{ip}:{port}"
        who = f"pid {pid}, {proc}" if pid else proc or "unknown process"

        if port in _DB_PORTS:
            db = _DB_PORTS[port]
            if exposed:
                findings.append(Finding(
                    rule=_rule(
                        "HOST_DB_EXPOSED", f"{db} database exposed to the network",
                        Severity.HIGH,
                        f"A {db} database is listening on all interfaces ({ip}).",
                        f"A {db} port reachable from the network is a classic breach vector — "
                        "often it has a weak or default password, or none. Anyone on the "
                        "network (or the internet, if the machine is public) can try to connect.",
                        f"Bind {db} to 127.0.0.1 only (in its config), require a strong password, "
                        "and block the port at the firewall.",
                        ["https://cwe.mitre.org/data/definitions/1327.html"],
                    ),
                    path=where, line=0, column=0, evidence=f"{db} listening on {where} ({who})",
                ))
            else:
                findings.append(Finding(
                    rule=_rule(
                        "HOST_DB_LOCAL", f"{db} database running (localhost only)",
                        Severity.INFO,
                        f"A {db} database is listening on localhost ({ip}).",
                        "Localhost-only is the safe binding. Noted so you know it is running.",
                        "No action needed unless you did not expect it — then stop the service.",
                    ),
                    path=where, line=0, column=0, evidence=f"{db} on {where} ({who})",
                ))
        elif exposed and (port in _DEV_PORTS or base in _DEV_PROCS):
            label = _DEV_PORTS.get(port, "development server")
            findings.append(Finding(
                rule=_rule(
                    "HOST_DEV_SERVER_EXPOSED", "Development server exposed to the network",
                    Severity.MEDIUM,
                    f"A {label} is listening on all interfaces ({ip}).",
                    "Dev servers have no hardening, often expose debug endpoints and source, "
                    "and are meant for localhost. Bound to 0.0.0.0 they are reachable by anyone "
                    "on your network.",
                    "Bind the dev server to 127.0.0.1 (e.g. Vite `server.host` off, Flask "
                    "host='127.0.0.1'), or stop it when you're done.",
                    ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                ),
                path=where, line=0, column=0, evidence=f"{label} on {where} ({who})",
            ))

    findings.extend(_firewall_findings())
    findings.sort(key=lambda f: (-f.rule.severity.rank, f.path))
    return findings


def host_summary() -> str:
    """A one-line context summary of the listening surface (not a finding)."""
    if not psutil_available():
        return ""
    total = local = exposed = 0
    for ip, _port, _pid, _proc in _listening_sockets():
        total += 1
        if _is_exposed(ip):
            exposed += 1
        else:
            local += 1
    return (
        f"{total} listening ports: {local} localhost-only (normal), "
        f"{exposed} reachable from the network."
    )
