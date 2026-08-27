
CREATE TABLE public.agent_sessions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  external_key TEXT UNIQUE,
  label TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_tasks (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
  idempotency_key TEXT,
  objective TEXT NOT NULL,
  success_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
  autonomous BOOLEAN NOT NULL DEFAULT true,
  priority INTEGER NOT NULL DEFAULT 5,
  state TEXT NOT NULL DEFAULT 'pending',
  phase TEXT NOT NULL DEFAULT 'created',
  trace_id TEXT NOT NULL,
  error JSONB,
  final_response TEXT,
  final_writer_alias TEXT,
  state_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  version INTEGER NOT NULL DEFAULT 1,
  continuation_token TEXT,
  human_request JSONB,
  human_input JSONB,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ,
  scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_tasks_idem_idx ON public.agent_tasks(session_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX agent_tasks_state_idx ON public.agent_tasks(state, priority DESC, scheduled_at);

CREATE TABLE public.agent_agents (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID NOT NULL REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES public.agent_agents(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  alias TEXT NOT NULL,
  instruction TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  depth INTEGER NOT NULL DEFAULT 0,
  workspace_path TEXT,
  result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_events (
  id BIGSERIAL PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  agent_id UUID REFERENCES public.agent_agents(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_events_task_idx ON public.agent_events(task_id, id);

CREATE TABLE public.agent_artifacts (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  agent_id UUID REFERENCES public.agent_agents(id) ON DELETE SET NULL,
  path TEXT NOT NULL,
  mime_type TEXT NOT NULL DEFAULT 'text/plain',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT,
  content TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_tool_calls (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  agent_id UUID REFERENCES public.agent_agents(id) ON DELETE SET NULL,
  tool TEXT NOT NULL,
  provider TEXT,
  input JSONB NOT NULL DEFAULT '{}'::jsonb,
  output JSONB,
  status TEXT NOT NULL DEFAULT 'running',
  error TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);

CREATE TABLE public.agent_sandboxes (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'instavm',
  remote_id TEXT,
  status TEXT NOT NULL DEFAULT 'provisioning',
  workspace_path TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_browser_sessions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  sandbox_id UUID REFERENCES public.agent_sandboxes(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open',
  current_url TEXT,
  history JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_sources (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  url TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  title TEXT,
  snippet TEXT,
  published_at TIMESTAMPTZ,
  score DOUBLE PRECISION,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_sources_dedup_idx ON public.agent_sources(task_id, canonical_url);

CREATE TABLE public.agent_mcp_servers (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  transport TEXT NOT NULL DEFAULT 'http',
  auth_credential TEXT,
  tools JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'registered',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_credentials (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_leases (
  name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.agent_audit (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT ALL ON public.agent_sessions TO service_role;
GRANT ALL ON public.agent_tasks TO service_role;
GRANT ALL ON public.agent_agents TO service_role;
GRANT ALL ON public.agent_events TO service_role;
GRANT ALL ON public.agent_artifacts TO service_role;
GRANT ALL ON public.agent_tool_calls TO service_role;
GRANT ALL ON public.agent_sandboxes TO service_role;
GRANT ALL ON public.agent_browser_sessions TO service_role;
GRANT ALL ON public.agent_sources TO service_role;
GRANT ALL ON public.agent_mcp_servers TO service_role;
GRANT ALL ON public.agent_credentials TO service_role;
GRANT ALL ON public.agent_leases TO service_role;
GRANT ALL ON public.agent_audit TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.agent_events_id_seq TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.agent_audit_id_seq TO service_role;

ALTER TABLE public.agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_sandboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_audit ENABLE ROW LEVEL SECURITY;
