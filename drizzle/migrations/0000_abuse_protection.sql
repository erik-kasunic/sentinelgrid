CREATE TABLE public.lookup_cache (
  cache_key text PRIMARY KEY,
  result jsonb NOT NULL,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  ttl_seconds integer NOT NULL
);
GRANT ALL ON public.lookup_cache TO service_role;
ALTER TABLE public.lookup_cache ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.rate_events (
  id bigserial PRIMARY KEY,
  ip_hash text NOT NULL,
  kind text NOT NULL DEFAULT 'lookup',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rate_events_ip_time ON public.rate_events (ip_hash, created_at DESC);
GRANT ALL ON public.rate_events TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.rate_events_id_seq TO service_role;
ALTER TABLE public.rate_events ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.provider_usage (
  id bigserial PRIMARY KEY,
  provider text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX provider_usage_provider_time ON public.provider_usage (provider, created_at DESC);
GRANT ALL ON public.provider_usage TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.provider_usage_id_seq TO service_role;
ALTER TABLE public.provider_usage ENABLE ROW LEVEL SECURITY;