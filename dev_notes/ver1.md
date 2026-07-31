# vuln-identifier-agent — recon slice

Step 1 of the build: an isolated lab (Juice Shop + Postgres + Neo4j) and a
deterministic recon agent that scans the target and writes structured
findings into the audit log and the recon graph. No LLM, no orchestrator,
no exploit agent yet — this is the ground-truth layer everything else sits on.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2) running locally.

## Run it

```bash
.env # local set up neo4j and postgres pwds
docker compose up -d postgres neo4j juice-shop
docker compose logs -f postgres neo4j    # wait for both healthchecks to pass
```

Then load the Neo4j schema (constraints) once:

```bash
docker compose exec neo4j cypher-shell -u neo4j -p changeme123 -f /dev/stdin < db/neo4j/schema.cypher
```

(If you changed `NEO4J_PASSWORD` in `.env`, use that instead of `changeme123`.)

Now run the recon agent:

```bash
docker compose up --build recon-agent
```

You'll see it wait for Postgres/Neo4j healthchecks, scan `juice-shop` on the
labnet, fingerprint the HTTP service, and log its progress to stdout.

## Verify it worked

**Postgres — audit trail:**

```bash
docker compose exec postgres psql -U vuln_agent -d vuln_agent \
  -c "SELECT id, agent_name, tool_name, status, created_at FROM agent_actions ORDER BY id;"
```

You should see two rows: `nmap_scan` and `http_fingerprint`, both `status = ok`.

**Neo4j — recon graph:**

Open http://localhost:7474 in a browser, log in with `neo4j` / your password, and run:

```cypher
MATCH (h:Host)-[:RUNS]->(s:Service) RETURN h, s;
```

You should see one `Host` node (the juice-shop container) connected to a
`Service` node for port 3000, with `product`/`version` populated from nmap
and `http_server_header`/`http_title` populated from the fingerprint step.

## What's deliberately not here yet

- **Orchestrator / LLM reasoning.** The plan is to get this recon step
  fully deterministic and verified first, then wire an orchestrator
  (LangGraph) on top that calls this as a tool and reasons over the
  Neo4j graph — not over raw nmap output.
- **Exploit agent.** Scoped separately, against specific named Juice Shop
  challenges, with the same hardcoded-allowlist pattern used here
  (`ALLOWED_TARGETS` in `recon-agent`'s environment — the agent refuses to
  scan anything not on that list, checked in code before any subprocess runs).
- **Report writer.** Reads from Postgres + Neo4j once there's more than one
  engagement's worth of data to summarize.

## Isolation notes

- The `labnet` docker network is `internal: true` — no container on it can
  reach the public internet. This also blocks Docker's host-to-container
  port-publishing NAT rules, so a container attached only to `labnet` is
  unreachable from your host even with a `ports:` entry — `internal: true`
  isolates both directions, not just outbound.
- To still let you reach `juice-shop`, `postgres`, and `neo4j` from a
  browser/CLI on your host, they're each dual-homed onto a second network,
  `hostnet`, which is a normal (non-internal) bridge. `recon-agent` is
  deliberately left off `hostnet`, so its own traffic stays fully contained
  by `labnet`'s isolation.
- `recon-agent`'s target is constrained by `ALLOWED_TARGETS`, checked in
  `recon_agent.py` before any nmap subprocess is spawned. Extend this list
  deliberately, not by removing the check.
