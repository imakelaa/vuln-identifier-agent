"""
Recon agent — deterministic, no LLM.

Scans a target on the isolated labnet, parses results with stdlib code
(not a model), and writes structured findings to Postgres (audit log) and
Neo4j (recon graph). This is step 1 of the pipeline: get ground-truth
recon working before any agent reasoning sits on top of it.

Scope guardrail: TARGET_HOST must appear in ALLOWED_TARGETS or the agent
refuses to run. This is enforced in code, not by prompting — the allowlist
check happens before any subprocess is invoked.
"""

import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import psycopg2
import requests
from neo4j import GraphDatabase

TARGET_HOST = os.environ["TARGET_HOST"]
TARGET_PORT = os.environ.get("TARGET_PORT", "3000")
ALLOWED_TARGETS = set(os.environ.get("ALLOWED_TARGETS", "").split(","))

PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_USER = os.environ.get("POSTGRES_USER", "vuln_agent")
PG_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "changeme")
PG_DB = os.environ.get("POSTGRES_DB", "vuln_agent")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme123")


def wait_for(name, fn, retries=20, delay=3):
    for attempt in range(1, retries + 1):
        try:
            fn()
            print(f"[recon-agent] {name} is ready", flush=True)
            return
        except Exception as exc:
            print(f"[recon-agent] waiting for {name} ({attempt}/{retries}): {exc}", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"{name} never became ready")


def pg_connect():
    return psycopg2.connect(host=PG_HOST, user=PG_USER, password=PG_PASSWORD, dbname=PG_DB)


def enforce_allowlist(target):
    if target not in ALLOWED_TARGETS:
        raise PermissionError(
            f"refusing to scan '{target}': not in ALLOWED_TARGETS ({sorted(ALLOWED_TARGETS)})"
        )


def run_nmap(target):
    """Run nmap with XML output, parse deterministically with stdlib ElementTree.
    Returns a list of {port, protocol, state, service, product, version}.
    """
    cmd = ["nmap", "-sV", "-p-", "-T4", "--max-retries", "2", "-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed (rc={result.returncode}): {result.stderr[:500]}")

    root = ET.fromstring(result.stdout)
    ports_found = []
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports_found.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol"),
                "state": state_el.get("state"),
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
            })
    return ports_found


def http_fingerprint(target, port):
    """Cheap deterministic HTTP banner grab — headers + title, no LLM involved."""
    url = f"http://{target}:{port}/"
    resp = requests.get(url, timeout=10)
    title = None
    if "<title>" in resp.text.lower():
        start = resp.text.lower().find("<title>") + len("<title>")
        end = resp.text.lower().find("</title>", start)
        title = resp.text[start:end].strip() if end > start else None
    return {
        "url": url,
        "status_code": resp.status_code,
        "server_header": resp.headers.get("Server"),
        "x_powered_by": resp.headers.get("X-Powered-By"),
        "title": title,
    }


def log_action(pg_conn, engagement_id, agent_name, tool_name, args, output, status):
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO agent_actions (engagement_id, agent_name, tool_name, args, output, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (engagement_id, agent_name, tool_name, json.dumps(args), json.dumps(output), status),
        )
    pg_conn.commit()


def write_graph(driver, host_ip, ports_found, http_info):
    with driver.session() as session:
        session.run("MERGE (h:Host {ip: $ip})", ip=host_ip)
        for p in ports_found:
            service_id = f"{host_ip}:{p['port']}/{p['protocol']}"
            session.run(
                """
                MATCH (h:Host {ip: $ip})
                MERGE (s:Service {id: $service_id})
                SET s.port = $port, s.protocol = $protocol, s.name = $service,
                    s.product = $product, s.version = $version
                MERGE (h)-[:RUNS]->(s)
                """,
                ip=host_ip,
                service_id=service_id,
                port=p["port"],
                protocol=p["protocol"],
                service=p["service"],
                product=p["product"],
                version=p["version"],
            )
            if http_info and p["port"] == int(TARGET_PORT):
                session.run(
                    """
                    MATCH (s:Service {id: $service_id})
                    SET s.http_server_header = $server_header,
                        s.http_powered_by = $powered_by,
                        s.http_title = $title
                    """,
                    service_id=service_id,
                    server_header=http_info.get("server_header"),
                    powered_by=http_info.get("x_powered_by"),
                    title=http_info.get("title"),
                )


def main():
    print(f"[recon-agent] target={TARGET_HOST} allowlist={sorted(ALLOWED_TARGETS)}", flush=True)
    enforce_allowlist(TARGET_HOST)

    pg_conn = None
    driver = None
    wait_for("postgres", lambda: pg_connect().close())
    wait_for("neo4j", lambda: GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)).verify_connectivity())

    pg_conn = pg_connect()
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    with pg_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO engagements (target, status) VALUES (%s, %s) RETURNING id",
            (TARGET_HOST, "running"),
        )
        engagement_id = cur.fetchone()[0]
    pg_conn.commit()
    print(f"[recon-agent] engagement_id={engagement_id}", flush=True)

    try:
        print(f"[recon-agent] running nmap against {TARGET_HOST} ...", flush=True)
        ports_found = run_nmap(TARGET_HOST)
        log_action(pg_conn, engagement_id, "recon", "nmap_scan",
                   {"target": TARGET_HOST}, {"ports": ports_found}, "ok")
        print(f"[recon-agent] found {len(ports_found)} open port(s): {ports_found}", flush=True)

        http_info = None
        target_port = int(TARGET_PORT)
        if any(p["port"] == target_port for p in ports_found):
            print(f"[recon-agent] fingerprinting http on port {target_port} ...", flush=True)
            http_info = http_fingerprint(TARGET_HOST, target_port)
            log_action(pg_conn, engagement_id, "recon", "http_fingerprint",
                       {"target": TARGET_HOST, "port": target_port}, http_info, "ok")
            print(f"[recon-agent] http fingerprint: {http_info}", flush=True)

        # resolve TARGET_HOST to the IP nmap actually reported, fall back to hostname
        host_ip = TARGET_HOST
        write_graph(driver, host_ip, ports_found, http_info)
        print("[recon-agent] wrote findings to Neo4j", flush=True)

        with pg_conn.cursor() as cur:
            cur.execute(
                "UPDATE engagements SET status = %s, ended_at = %s WHERE id = %s",
                ("completed", datetime.now(timezone.utc), engagement_id),
            )
        pg_conn.commit()
        print("[recon-agent] done", flush=True)

    except Exception as exc:
        log_action(pg_conn, engagement_id, "recon", "recon_run", {"target": TARGET_HOST}, {"error": str(exc)}, "error")
        with pg_conn.cursor() as cur:
            cur.execute("UPDATE engagements SET status = %s WHERE id = %s", ("failed", engagement_id))
        pg_conn.commit()
        print(f"[recon-agent] FAILED: {exc}", file=sys.stderr, flush=True)
        raise
    finally:
        pg_conn.close()
        driver.close()


if __name__ == "__main__":
    main()
