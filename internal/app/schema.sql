CREATE TABLE IF NOT EXISTS schema_version(version int PRIMARY KEY);
INSERT INTO schema_version VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS config_version(id boolean PRIMARY KEY DEFAULT true CHECK(id), version bigint NOT NULL DEFAULT 1);
INSERT INTO config_version(id) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS administrators(id bigserial PRIMARY KEY, username text UNIQUE NOT NULL, password_hash text NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash text PRIMARY KEY, admin_id bigint NOT NULL REFERENCES administrators, csrf text NOT NULL, expires_at timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_limits(bucket text PRIMARY KEY, attempts int NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS acme_accounts(id bigserial PRIMARY KEY, directory text UNIQUE NOT NULL, email text NOT NULL, key_cipher bytea NOT NULL, key_id text NOT NULL, account_url text NOT NULL, tos_accepted_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS certificates(id bigserial PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120), origin text NOT NULL CHECK(origin IN ('upload','acme')), domains text[] NOT NULL, chain_pem text NOT NULL DEFAULT '', key_cipher bytea, key_id text, issuer text NOT NULL DEFAULT '', not_before timestamptz, not_after timestamptz, account_id bigint REFERENCES acme_accounts, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sites(id bigserial PRIMARY KEY, name text NOT NULL, hostnames text[] NOT NULL, upstream text NOT NULL, certificate_id bigint REFERENCES certificates, redirect_https boolean NOT NULL DEFAULT true, preserve_host boolean NOT NULL DEFAULT true, enabled boolean NOT NULL DEFAULT true);
CREATE TABLE IF NOT EXISTS site_hosts(hostname text PRIMARY KEY, site_id bigint NOT NULL REFERENCES sites ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS jobs(id bigserial PRIMARY KEY, certificate_id bigint NOT NULL REFERENCES certificates, status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','retry','succeeded')), attempts int NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(), error text NOT NULL DEFAULT '', owner text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS one_active_job ON jobs(certificate_id) WHERE status IN ('queued','running','retry');
CREATE TABLE IF NOT EXISTS acme_orders(id bigserial PRIMARY KEY, job_id bigint NOT NULL REFERENCES jobs, url text NOT NULL, status text NOT NULL, error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS acme_challenges(hostname text NOT NULL, token text NOT NULL, response text NOT NULL, job_id bigint NOT NULL REFERENCES jobs, expires_at timestamptz NOT NULL, PRIMARY KEY(hostname,token));
CREATE TABLE IF NOT EXISTS audit_events(id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, resource text NOT NULL);
CREATE TABLE IF NOT EXISTS access_logs(id bigserial PRIMARY KEY, at timestamptz NOT NULL, site_id bigint NOT NULL, method text NOT NULL, status int NOT NULL, duration_ms bigint NOT NULL, peer text NOT NULL);
CREATE INDEX IF NOT EXISTS access_logs_at ON access_logs(at);
-- Version 2: bounded declarative rules and opt-in, expiring traffic evidence.
CREATE TABLE IF NOT EXISTS rules(id bigserial PRIMARY KEY, site_id bigint NOT NULL REFERENCES sites ON DELETE CASCADE, spec jsonb NOT NULL, enabled boolean NOT NULL DEFAULT false, expires_at timestamptz, revision bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS rules_site ON rules(site_id);
CREATE TABLE IF NOT EXISTS rule_revisions(id bigserial PRIMARY KEY, rule_id bigint NOT NULL REFERENCES rules ON DELETE CASCADE, spec jsonb NOT NULL, enabled boolean NOT NULL, expires_at timestamptz, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_settings(site_id bigint PRIMARY KEY REFERENCES sites ON DELETE CASCADE, settings jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_evidence(id text PRIMARY KEY, at timestamptz NOT NULL, site_id bigint NOT NULL REFERENCES sites ON DELETE CASCADE, expires_at timestamptz NOT NULL, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS traffic_evidence_site_at ON traffic_evidence(site_id,at DESC);
CREATE INDEX IF NOT EXISTS traffic_evidence_expiry ON traffic_evidence(expires_at);
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS rule_results jsonb NOT NULL DEFAULT '[]';
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS event_id text NOT NULL DEFAULT '';
INSERT INTO schema_version VALUES (2) ON CONFLICT DO NOTHING;
-- Version 3: encrypted Cloudflare DNS credentials and per-certificate challenge selection.
CREATE TABLE IF NOT EXISTS dns_credentials(id bigserial PRIMARY KEY,name text NOT NULL,token_cipher bytea NOT NULL,key_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS challenge_type text NOT NULL DEFAULT 'http-01' CHECK(challenge_type IN ('http-01','dns-01'));
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS dns_credential_id bigint REFERENCES dns_credentials(id);
INSERT INTO schema_version VALUES(3) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS dns_challenges(id bigserial PRIMARY KEY,job_id bigint NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,credential_id bigint NOT NULL REFERENCES dns_credentials(id),zone_id text NOT NULL,record_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS dns_challenges_job ON dns_challenges(job_id);

-- Version 4: per-application protection and replica telemetry.
CREATE TABLE IF NOT EXISTS protection_settings(site_id bigint PRIMARY KEY REFERENCES sites ON DELETE CASCADE, settings jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS geo_database(id boolean PRIMARY KEY DEFAULT true CHECK(id), data bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS replica_metrics(id text PRIMARY KEY, at timestamptz NOT NULL, data jsonb NOT NULL);
ALTER TABLE replica_metrics ADD COLUMN IF NOT EXISTS dropped_logs bigint NOT NULL DEFAULT 0;
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS country text NOT NULL DEFAULT '';
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS blocked boolean NOT NULL DEFAULT false;
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS signals jsonb NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS access_logs_site_at ON access_logs(site_id,at);
INSERT INTO schema_version VALUES(4) ON CONFLICT DO NOTHING;

-- Version 5: source candidates are separate from live rules.
CREATE TABLE IF NOT EXISTS rule_feeds(id serial PRIMARY KEY,name text NOT NULL,url text NOT NULL,site_id bigint NOT NULL REFERENCES sites ON DELETE CASCADE,etag text NOT NULL DEFAULT '',last_attempt timestamptz,last_success timestamptz,next_sync timestamptz NOT NULL DEFAULT now(),error text NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS rule_feed_items(feed_id int NOT NULL REFERENCES rule_feeds ON DELETE CASCADE,entry_id text NOT NULL,spec jsonb NOT NULL,available boolean NOT NULL DEFAULT true,imported_spec jsonb,rule_id bigint REFERENCES rules ON DELETE SET NULL,PRIMARY KEY(feed_id,entry_id));
INSERT INTO schema_version VALUES(5) ON CONFLICT DO NOTHING;

-- Version 6: per-application headers and scoped protection exceptions.
CREATE TABLE IF NOT EXISTS proxy_headers(site_id bigint PRIMARY KEY REFERENCES sites ON DELETE CASCADE,settings jsonb NOT NULL);
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS protection_exemptions jsonb NOT NULL DEFAULT '[]';
INSERT INTO schema_version VALUES(6) ON CONFLICT DO NOTHING;

-- Version 7: provider connection settings and reusable source-scoped policies.
CREATE TABLE IF NOT EXISTS ai_provider(id boolean PRIMARY KEY DEFAULT true CHECK(id),base_url text NOT NULL,key_cipher bytea,key_id text NOT NULL,model text NOT NULL,models jsonb NOT NULL,checked_at timestamptz,revision bigint NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS policies(id bigserial PRIMARY KEY,spec jsonb NOT NULL,revision bigint NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS policy_assignments(policy_id bigint NOT NULL REFERENCES policies ON DELETE CASCADE,site_id bigint NOT NULL REFERENCES sites ON DELETE CASCADE,source_cidrs text[] NOT NULL,priority int NOT NULL,PRIMARY KEY(policy_id,site_id),UNIQUE(site_id,priority),CHECK((cardinality(source_cidrs)=0 AND priority=10000) OR(cardinality(source_cidrs)>0 AND priority>=0 AND priority<10000)));
CREATE TABLE IF NOT EXISTS policy_revisions(policy_id bigint NOT NULL REFERENCES policies ON DELETE CASCADE,revision bigint NOT NULL,spec jsonb NOT NULL,actor text NOT NULL,at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(policy_id,revision));
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS policy_id bigint NOT NULL DEFAULT 0;
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS policy_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS policy_name text NOT NULL DEFAULT '';
INSERT INTO schema_version VALUES(7) ON CONFLICT DO NOTHING;

ALTER TABLE replica_metrics ADD COLUMN IF NOT EXISTS system jsonb NOT NULL DEFAULT '{}';

-- Version 8: immutable managed signature bundles and request-inspection metadata.
CREATE TABLE IF NOT EXISTS signature_sets(id text PRIMARY KEY,name text NOT NULL,version text NOT NULL,digest text NOT NULL,rule_count int NOT NULL,files jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS managed_signatures jsonb NOT NULL DEFAULT '{}';
INSERT INTO schema_version VALUES(8) ON CONFLICT DO NOTHING;

-- Version 9: one-time provisioned baseline policy, editable and removable.
CREATE TABLE IF NOT EXISTS built_in_policies(key text PRIMARY KEY,policy_id bigint REFERENCES policies ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO schema_version VALUES(9) ON CONFLICT DO NOTHING;
