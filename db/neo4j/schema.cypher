// Recon graph schema. Run once after Neo4j is up.
// Model: (Host)-[:RUNS]->(Service)-[:HAS_VULN]->(Vuln)-[:EXPLOITABLE_VIA]->(ExploitPath)

CREATE CONSTRAINT host_ip IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

CREATE CONSTRAINT service_id IF NOT EXISTS
FOR (s:Service) REQUIRE s.id IS UNIQUE;   // id = "<host_ip>:<port>/<proto>"

CREATE CONSTRAINT vuln_id IF NOT EXISTS
FOR (v:Vuln) REQUIRE v.id IS UNIQUE;      // e.g. CVE id or a challenge name for lab apps

CREATE CONSTRAINT exploit_id IF NOT EXISTS
FOR (e:ExploitPath) REQUIRE e.id IS UNIQUE;

// Example shape once recon + exploit agents are both writing:
// (:Host {ip:"172.28.0.10"})
//   -[:RUNS]->(:Service {id:"172.28.0.10:3000/tcp", name:"http", product:"Express", version:"..."})
//     -[:HAS_VULN]->(:Vuln {id:"juice-shop:score-board", severity:"info"})
//       -[:EXPLOITABLE_VIA]->(:ExploitPath {id:"...", status:"untried"})
