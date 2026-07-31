-- Engagement + action audit trail.
-- This is the ground-truth log: every tool call any agent makes gets a row here,
-- independent of whatever the LLM later says happened.

CREATE TABLE IF NOT EXISTS engagements (
    id           SERIAL PRIMARY KEY,
    target       VARCHAR(255) NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at     TIMESTAMPTZ,
    status       VARCHAR(50) NOT NULL DEFAULT 'running'  -- running | completed | failed
);

CREATE TABLE IF NOT EXISTS agent_actions (
    id             SERIAL PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    agent_name     VARCHAR(100) NOT NULL,   -- 'recon' | 'exploit' | 'report-writer'
    tool_name      VARCHAR(100) NOT NULL,   -- 'nmap_scan' | 'http_fingerprint' | ...
    args           JSONB,
    output         JSONB,
    status         VARCHAR(50) NOT NULL,    -- ok | error | refused
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_actions_engagement ON agent_actions(engagement_id);
CREATE INDEX IF NOT EXISTS idx_agent_actions_agent_name ON agent_actions(agent_name);
