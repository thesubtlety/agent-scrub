#!/usr/bin/env python3
"""Regenerates Fixtures/. Every credential here is synthetic: bodies are FAKE-patterned, and GitHub
classic tokens carry a valid CRC32 checksum only so the detector's offline validation exercises the
real code path. None of these values is a working credential."""
import json, os, pathlib, shutil, zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
F = ROOT / "Fixtures"

B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
def gh_token(prefix, body30):
    assert len(body30) == 30
    crc = zlib.crc32(body30.encode()) & 0xFFFFFFFF
    s = ""
    while crc:
        s = B62[crc % 62] + s; crc //= 62
    return prefix + body30 + s.rjust(6, "0")

import hashlib
def synth(seed: str, n: int, alphabet: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") -> str:
    """Deterministic high-entropy body so detectors' entropy gates see a credential-shaped value.
    Still synthetic: derived from a fixed label, never issued by any service."""
    out = ""
    counter = 0
    while len(out) < n:
        digest = hashlib.sha256(f"history-guard-fixture:{seed}:{counter}".encode()).digest()
        out += "".join(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return out[:n]

GH    = gh_token("ghp_", "FAKE" + synth("github-pat", 26))
GH2   = gh_token("gho_", "FAKE" + synth("github-oauth", 26))
GH_BADSUM = "ghp_" + "FAKE" + synth("github-pat", 26) + "000000"
AKIA  = "AKIA" + "FAKE" + synth("aws-key-id", 12, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
AWSS  = "FAKE" + synth("aws-secret", 34, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+") + "=="
STRIPE = "sk_test_" + "FAKE" + synth("stripe", 20)
SLACK = "xoxb-" + "1234567890123" + "-" + "1234567890123" + "-" + "FAKE" + synth("slack", 20)
ANTH  = "sk-ant-oat01-" + "FAKE" + synth("anthropic-oauth", 60) + "AA"
DBURL = "postgres://app:FAKEpassw0rd@db.payments.internal:5432/payments"
JWT   = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIiwiaWF0IjoxNzkwMDAwMDAwfQ." + "FAKE" + synth("jwt-sig", 39)
PEM   = ("-----BEGIN RSA PRIVATE KEY-----\n"
         "MIIFAKE" + synth("pem-1", 57) + "\n"
         + synth("pem-2", 64) + "\n"
         + synth("pem-3", 36) + "=\n"
         "-----END RSA PRIVATE KEY-----")
KEYED = "Xq9!vT2#kL8mZp4wR7"

def write_secret_corpus():
    pos = [
      {"id":"github-pat","text":f"please use {GH} to check the repo","kind":"githubToken","minConfidence":"high","count":1},
      {"id":"github-in-env","text":f"GITHUB_TOKEN={GH}\n","kind":"githubToken","minConfidence":"high","count":1},
      {"id":"github-oauth","text":f"token: {GH2}","kind":"githubToken","minConfidence":"high","count":1},
      {"id":"aws-key-id","text":f"aws_access_key_id = {AKIA}","kind":"awsAccessKeyID","minConfidence":"high","count":1},
      {"id":"aws-secret","text":f"aws_secret_access_key = {AWSS}","kind":"awsSecretAccessKey","minConfidence":"high","count":1},
      {"id":"stripe","text":f"export STRIPE_SECRET_KEY={STRIPE}","kind":"stripeKey","minConfidence":"high","count":1},
      {"id":"slack","text":f"slack bot token: {SLACK}","kind":"slackToken","minConfidence":"high","count":1},
      {"id":"anthropic","text":f'{{"accessToken":"{ANTH}"}}',"kind":"anthropicKey","minConfidence":"high","count":1},
      {"id":"db-url","text":f"DATABASE_URL={DBURL}","kind":"databaseURL","minConfidence":"high","count":1},
      {"id":"db-url-trailing-period","text":f"see {DBURL}.","kind":"databaseURL","minConfidence":"high","count":1},
      {"id":"pem","text":f"here is the key:\n{PEM}\nthanks","kind":"privateKey","minConfidence":"high","count":1},
      {"id":"jwt","text":f"Authorization: Bearer {JWT}","kind":"jwt","minConfidence":"medium","count":1},
      {"id":"bearer-opaque","text":"GET /v1/me HTTP/1.1\nAuthorization: Bearer FAKEbearerTokenValue0123456789xyz\n","kind":"bearerToken","minConfidence":"medium","count":1},
      {"id":"bearer-in-curl","text":"curl -H 'Authorization: Bearer FAKEbearerTokenValue0123456789xyz' https://api.internal/","kind":"vendorAPIKey","minConfidence":"high","count":1},
      {"id":"keyed-password","text":f"DATABASE_PASSWORD={KEYED}","kind":"genericSecret","minConfidence":"medium","count":1},
      {"id":"keyed-json","text":f'{{"password": "{KEYED}"}}',"kind":"genericSecret","minConfidence":"medium","count":1},
      {"id":"repeated","text":f"{GH} and again {GH}","kind":"githubToken","minConfidence":"high","count":2},
      {"id":"two-kinds","text":f"{AKIA} / {AWSS} in aws_secret_access_key={AWSS}","kind":"awsAccessKeyID","minConfidence":"high","count":1},
    ]
    neg = [
      {"id":"ssh-public-key","text":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE user@host"},
      {"id":"certificate","text":"-----BEGIN CERTIFICATE-----\nMIIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n-----END CERTIFICATE-----"},
      {"id":"env-interpolation","text":"GITHUB_TOKEN=${GITHUB_TOKEN}"},
      {"id":"angle-placeholder","text":"api_key=<YOUR_API_KEY>"},
      {"id":"env-example","text":"API_KEY=your-api-key-here\nSECRET_KEY=changeme"},
      {"id":"word-password","text":"password=password"},
      {"id":"process-env","text":"token: process.env.API_TOKEN"},
      {"id":"aws-doc-example","text":"AKIAIOSFODNN7EXAMPLE"},
      {"id":"sha256","text":"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"id":"uuid","text":"id = 847ab000-0000-4000-8000-000000000001"},
      {"id":"same-char","text":'secret = "xxxxxxxxxxxxxxxx"'},
      {"id":"code","text":"const token = getToken();\nconst secret = req.headers.authorization;"},
      {"id":"length-var","text":"TOKEN_LENGTH=32"},
      {"id":"example-url","text":"postgres://user:password@db.example.com/app"},
      {"id":"bearer-placeholder","text":"Authorization: Bearer <token>"},
      {"id":"bearer-var","text":"Authorization: Bearer $ACCESS_TOKEN"},
    ]
    (F/"Secrets").mkdir(parents=True, exist_ok=True)
    json.dump(pos, open(F/"Secrets/positive.json","w"), indent=2)
    json.dump(neg, open(F/"Secrets/negative.json","w"), indent=2)
    json.dump({"github":GH,"githubOAuth":GH2,"awsKeyID":AKIA,"awsSecret":AWSS,"stripe":STRIPE,"slack":SLACK,
               "anthropic":ANTH,"dbURL":DBURL,"jwt":JWT,"pem":PEM,"keyed":KEYED},
              open(F/"Secrets/values.json","w"), indent=2)

def write_claude_version_a():
    base = F/"Claude/version-A"
    if base.exists(): shutil.rmtree(base)
    def w(rel, content, mode=None):
        p = base/rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        if mode: os.chmod(p, mode)
    def jl(rel, records):
        w(rel, "".join(json.dumps(r, separators=(",",":"))+"\n" for r in records))
    SLUG="-Users-dev-payments-api"; SID="847ab000-0000-4000-8000-000000000001"; T="2026-09-29T07:14:22.000Z"
    jl("history.jsonl", [
      {"display":"fix the flaky test in payments","pastedContents":{},"project":"/Users/dev/payments-api","sessionId":SID,"timestamp":1790000000000},
      {"display":"[Pasted text #1 +3 lines]","pastedContents":{"1":{"id":1,"type":"text","content":f"GITHUB_TOKEN={GH}\nAWS_REGION=us-east-1\n"}},"project":"/Users/dev/payments-api","sessionId":SID,"timestamp":1790000001000},
      {"display":f"connect with {DBURL} and list tables","pastedContents":{},"project":"/Users/dev/payments-api","sessionId":SID,"timestamp":1790000002000},
    ])
    jl(f"projects/{SLUG}/{SID}.jsonl", [
      {"type":"user","cwd":"/Users/dev/payments-api","sessionId":SID,"version":"2.1.200","gitBranch":"main","timestamp":T,"uuid":"u1","parentUuid":None,
       "message":{"role":"user","content":f"please use {GH} to check whether the workflow passed"}},
      {"type":"assistant","cwd":"/Users/dev/payments-api","sessionId":SID,"version":"2.1.200","timestamp":T,"uuid":"a1","parentUuid":"u1",
       "message":{"role":"assistant","model":"claude","content":[{"type":"text","text":f"I'll call the API with {GH} now."},
          {"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"aws sts get-caller-identity","description":"Check identity"}}]}},
      {"type":"user","cwd":"/Users/dev/payments-api","sessionId":SID,"version":"2.1.200","timestamp":T,"uuid":"u2","parentUuid":"a1",
       "message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":f"AWS_ACCESS_KEY_ID={AKIA}\naws_secret_access_key={AWSS}\n"}]},
       "toolUseResult":{"stdout":f"AWS_ACCESS_KEY_ID={AKIA}\naws_secret_access_key={AWSS}\n","stderr":"","interrupted":False}},
      {"type":"assistant","cwd":"/Users/dev/payments-api","sessionId":SID,"version":"2.1.200","timestamp":T,"uuid":"a2","parentUuid":"u2",
       "message":{"role":"assistant","content":[{"type":"text","text":"Here is the deploy key you pasted earlier:\n"+PEM+"\nStore it in a secret manager."}]}},
      {"type":"user","cwd":"/Users/dev/payments-api","sessionId":SID,"version":"2.1.200","timestamp":T,"uuid":"u3","parentUuid":"a2",
       "message":{"role":"user","content":"the token is quoted here: \""+GH+"\" — does that matter? café ünïcode nearby"}},
      {"type":"file-history-snapshot","messageId":"m1","snapshot":{"trackedFileBackups":{},"timestamp":T},"isSnapshotUpdate":False},
      {"type":"system","subtype":"turn_duration","durationMs":1234,"timestamp":T,"uuid":"s1","isMeta":True},
      {"type":"attachment","attachment":{"type":"queued_command","prompt":"continue"},"uuid":"at1","timestamp":T},
    ])
    jl(f"projects/{SLUG}/{SID}/subagents/agent-a1b2c3d4.jsonl", [
      {"type":"user","isSidechain":True,"sessionId":SID,"timestamp":T,"uuid":"sa1","message":{"role":"user","content":"Verify the token works"}},
      {"type":"assistant","isSidechain":True,"sessionId":SID,"timestamp":T,"uuid":"sa2","message":{"role":"assistant","content":[{"type":"text","text":f"Using {GH} against api.github.com returned 200."}]}},
    ])
    w(f"projects/{SLUG}/{SID}/subagents/agent-a1b2c3d4.meta.json", json.dumps({"agentType":"Explore","description":"Verify token","startedAt":T}))
    w(f"projects/{SLUG}/{SID}/tool-results/bx1abc2de.txt", f"$ env | grep -i token\nGITHUB_TOKEN={GH}\nSLACK_BOT_TOKEN={SLACK}\n" + "filler line\n"*50)
    w(f"projects/{SLUG}/{SID}/ccr-tip.json", json.dumps({"eventId":"evt_FAKE","updatedAt":1790000000000}))
    w(f"projects/{SLUG}/{SID}/unknown-thing.txt", "not a known store layout\n")
    w(f"projects/{SLUG}/bridge-pointer.json", json.dumps({"environmentId":"env_FAKE","pid":99999,"procStart":1,"sessionId":SID,"source":"remote"}))
    w(f"projects/{SLUG}/memory/MEMORY.md", f"# Memory\n\n- [DB access](db.md) — staging is {DBURL}\n")
    w(f"projects/{SLUG}/memory/db.md", "---\nname: db-access\n---\nUse the staging URL from MEMORY.md.\n")
    w("paste-cache/cbcb5ab17c9d306e.txt", PEM + "\n")
    w("shell-snapshots/snapshot-bash-1790000000000-abc123.sh", "# Snapshot file\nshopt -s expand_aliases\nalias ll='ls -la'\n"
      f"export STRIPE_SECRET_KEY={STRIPE}\nexport PATH=/usr/bin\n", 0o644)
    w(f"file-history/{SID}/0a1b2c3d4e5f@v1", f"# .env\nAWS_ACCESS_KEY_ID={AKIA}\nAWS_SECRET_ACCESS_KEY={AWSS}\n")
    w("bridge-spawn/cse_FAKE/append-system-prompt.txt", "You are running in bridge mode.\n")
    # excluded stores: these values must never appear in findings
    w(".credentials.json", json.dumps({"claudeAiOauth":{"accessToken":ANTH,"refreshToken":ANTH,"expiresAt":1790000000000,"scopes":["user:inference"]}}), 0o600)
    w("backups/.claude.json.backup.1790000000000", json.dumps({"oauthAccount":{"accountUuid":"x"},"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":GH}}}}))
    w("settings.json", json.dumps({"permissions":{"allow":["Bash(git:*)"]},"env":{"GITHUB_TOKEN":GH}}))
    w("CLAUDE.md", "# Global instructions\n")
    w("sessions/99999.json", json.dumps({"peerToken":"FAKE","pidDomain":"x","procStart":1}))
    w("sessions/99999.aaaaaaaaaaaaaaaa.key", "FAKEKEYMATERIAL\n", 0o600)
    w("plugins/installed_plugins.json", "{}")
    w("skills/example/SKILL.md", "---\nname: example\n---\n")
    w("state/mcp-discover-verdicts.json", "{}")
    # unknown root entry: must be a coverage gap and must NOT be scanned
    w("agent-scratch/notes.txt", f"scratch {GH}\n")
    (F/"Claude/.claude.json").write_text(json.dumps({"numStartups":3}))

def write_claude_malformed():
    M = F/"Claude/malformed"
    if M.exists(): shutil.rmtree(M)
    M.mkdir(parents=True)
    SID="847ab000-0000-4000-8000-000000000001"
    lines = [
      json.dumps({"display":"ok line","pastedContents":{},"project":"/p","sessionId":SID,"timestamp":1}),
      '{"display":"broken record with ' + GH + ' inside","pastedContents":{',
      json.dumps({"display":"another ok line","pastedContents":{},"project":"/p","sessionId":SID,"timestamp":3}),
    ]
    tail = '{"display":"truncated tail holding ' + GH + '","pastedContents":{"1":{"content":"partial'
    (M/"history.jsonl").write_text("\n".join(lines)+"\n"+tail)
    (M/"projects").mkdir(exist_ok=True)

def write_codex_version_a():
    import sqlite3
    base = F/"Codex/version-A"
    if base.exists(): shutil.rmtree(base)
    def w(rel, content, mode=None):
        p = base/rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        if mode: os.chmod(p, mode)
    def jl(rel, records):
        w(rel, "".join(json.dumps(r, separators=(",",":"))+"\n" for r in records))
    TID = "0199a3f0-0000-7000-8000-00000000c0de"; TID2 = "0199a3f0-0000-7000-8000-00000000a5c1"
    OPENAI = "sk-proj-" + synth("openai", 20) + "T3BlbkFJ" + synth("openai-2", 20)
    HTTPS_CREDS = f"https://deploy:{synth('git-pw', 24)}@github.com/acme/payments-api.git"

    jl("history.jsonl", [
      {"session_id": TID, "ts": 1790000000, "text": "fix the flaky payments test"},
      {"session_id": TID, "ts": 1790000001, "text": f"use {GH} to check the workflow"},
      {"session_id": TID2, "ts": 1790000002, "text": f"connect to {DBURL}"},
    ])
    T = "2026-09-29T07:14:22.000Z"
    jl(f"sessions/2026/09/29/rollout-2026-09-29T07-14-22-{TID}.jsonl", [
      {"timestamp": T, "type": "session_meta", "payload": {"id": TID, "timestamp": T, "cwd": "/Users/dev/payments-api", "originator": "codex_cli_rs", "cli_version": "0.99.0", "instructions": None, "source": "cli"}},
      {"timestamp": T, "type": "turn_context", "payload": {"cwd": "/Users/dev/payments-api", "approval_policy": "on-request", "model": "gpt-5-codex"}},
      {"timestamp": T, "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"use {GH} to check the workflow"}]}},
      {"timestamp": T, "type": "response_item", "payload": {"type": "function_call", "name": "shell", "arguments": json.dumps({"command": ["bash","-lc","env | grep AWS"]}), "call_id": "call_1"}},
      {"timestamp": T, "type": "response_item", "payload": {"type": "function_call_output", "call_id": "call_1", "output": f"AWS_ACCESS_KEY_ID={AKIA}\naws_secret_access_key={AWSS}\n"}},
      {"timestamp": T, "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": f"Done. I used {GH} against the API."}]}},
      {"timestamp": T, "type": "event_msg", "payload": {"type": "agent_message", "message": "Done."}},
    ])
    jl(f"archived_sessions/2026/09/01/rollout-2026-09-01T09-00-00-{TID2}.jsonl", [
      {"timestamp": "2026-09-01T09:00:00.000Z", "type": "session_meta", "payload": {"id": TID2, "cwd": "/Users/dev/infra", "cli_version": "0.98.0"}},
      {"timestamp": "2026-09-01T09:00:01.000Z", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"rotate {SLACK} please"}]}},
    ])
    w("sessions/2026/09/29/notes.txt", "not a rollout\n")
    jl("session_index.jsonl", [
      {"id": TID, "thread_name": f"workflow check with {GH}", "updated_at": T},
      {"id": TID2, "thread_name": "infra rotation", "updated_at": "2026-09-01T09:00:01Z"},
    ])
    db = sqlite3.connect(base/"state_5.sqlite")
    db.executescript("""
      CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        source TEXT NOT NULL, model_provider TEXT NOT NULL, cwd TEXT NOT NULL, title TEXT NOT NULL, sandbox_policy TEXT NOT NULL,
        approval_mode TEXT NOT NULL, tokens_used INTEGER NOT NULL DEFAULT 0, has_user_event INTEGER NOT NULL DEFAULT 0,
        archived INTEGER NOT NULL DEFAULT 0, archived_at INTEGER, git_sha TEXT, git_branch TEXT, git_origin_url TEXT,
        cli_version TEXT NOT NULL DEFAULT '', first_user_message TEXT NOT NULL DEFAULT '', preview TEXT NOT NULL DEFAULT '', name TEXT);
      CREATE TABLE thread_attachments (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, attachment_type TEXT NOT NULL, identity_key TEXT NOT NULL,
        payload TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMP NOT NULL, success BOOLEAN NOT NULL, checksum BLOB NOT NULL, execution_time BIGINT NOT NULL);
    """)
    db.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      (TID, f"sessions/2026/09/29/rollout-2026-09-29T07-14-22-{TID}.jsonl", 1790000000000, 1790000010000, "cli", "openai", "/Users/dev/payments-api",
       f"use {GH} to check the workflow", "workspace-write", "on-request", 1234, 1, 0, None, "abc123", "main", HTTPS_CREDS, "0.99.0",
       f"use {GH} to check the workflow", f"use {GH} to check the workflow", "Workflow check"))
    db.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      (TID2, f"archived_sessions/2026/09/01/rollout-2026-09-01T09-00-00-{TID2}.jsonl", 1788000000000, 1788000010000, "cli", "openai", "/Users/dev/infra",
       "infra rotation", "workspace-write", "on-request", 10, 1, 1, 1788000020000, None, None, None, "0.98.0", "rotate the slack token", "rotate the slack token", None))
    db.execute("INSERT INTO thread_attachments VALUES (?,?,?,?,?,?)",
      ("att_1", TID, "file", "env", json.dumps({"path": "/Users/dev/payments-api/.env", "content": f"STRIPE_SECRET_KEY={STRIPE}\n"}), 1790000005000))
    db.commit(); db.close()
    db = sqlite3.connect(base/"thread_history_1.sqlite")
    db.executescript("""
      CREATE TABLE thread_turns (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, status TEXT NOT NULL, error_json TEXT,
        started_at INTEGER, completed_at INTEGER, duration_ms INTEGER, first_user_item_id TEXT, final_agent_item_id TEXT, PRIMARY KEY (thread_id, turn_id));
      CREATE TABLE thread_items (thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL, item_json TEXT NOT NULL, item_type TEXT NOT NULL DEFAULT '', PRIMARY KEY (thread_id, turn_id, item_id));
      CREATE TABLE thread_realtime_items (thread_id TEXT NOT NULL, item_id TEXT NOT NULL, rollout_ordinal INTEGER NOT NULL, created_at_ms INTEGER NOT NULL,
        item_type TEXT NOT NULL, item_json TEXT NOT NULL, PRIMARY KEY (thread_id, item_id));
      CREATE TABLE thread_history_projection_state (thread_id TEXT PRIMARY KEY, next_rollout_byte_offset INTEGER NOT NULL, next_rollout_ordinal INTEGER NOT NULL);
    """)
    db.execute("INSERT INTO thread_turns VALUES (?,?,?,?,?,?,?,?,?,?)", (TID, "turn_1", 2, "completed", None, 1790000001000, 1790000009000, 8000, "item_1", "item_3"))
    db.execute("INSERT INTO thread_items VALUES (?,?,?,?,?,?,?)", (TID, "turn_1", "item_1", 2, 1790000001000,
      json.dumps({"type": "userMessage", "id": "item_1", "content": [{"type": "text", "text": f"use {GH} to check the workflow"}]}), "userMessage"))
    db.execute("INSERT INTO thread_items VALUES (?,?,?,?,?,?,?)", (TID, "turn_1", "item_3", 5, 1790000008000,
      json.dumps({"type": "agentMessage", "id": "item_3", "text": f"Done. I used {GH} against the API."}), "agentMessage"))
    db.execute("INSERT INTO thread_realtime_items VALUES (?,?,?,?,?,?)", (TID, "rt_1", 6, 1790000009000, "realtime_transcript",
      json.dumps({"type": "realtime_transcript", "text": f"the JWT is {JWT}"})))
    db.commit(); db.close()
    db = sqlite3.connect(base/"logs_2.sqlite")
    db.executescript("""
      CREATE TABLE logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ts_nanos INTEGER NOT NULL, level TEXT NOT NULL, target TEXT NOT NULL,
        feedback_log_body TEXT, module_path TEXT, file TEXT, line INTEGER, thread_id TEXT, process_uuid TEXT, estimated_bytes INTEGER NOT NULL DEFAULT 0);
    """)
    db.execute("INSERT INTO logs (ts, ts_nanos, level, target, feedback_log_body, thread_id) VALUES (?,?,?,?,?,?)",
      (1790000003, 0, "DEBUG", "codex_core::tools", f"tool output: GITHUB_TOKEN={GH}", TID))
    db.commit(); db.close()
    db = sqlite3.connect(base/"goals_1.sqlite")
    db.executescript("CREATE TABLE thread_goals (thread_id TEXT PRIMARY KEY, objective TEXT NOT NULL, status TEXT NOT NULL);")
    db.execute("INSERT INTO thread_goals VALUES (?,?,?)", (TID, f"ship it; db is {DBURL}", "active"))
    db.commit(); db.close()
    w("auth.json", json.dumps({"OPENAI_API_KEY": OPENAI, "tokens": {"access_token": JWT}}), 0o600)
    w("config.toml", 'model = "gpt-5-codex"\n')
    w("AGENTS.md", "# Agents\n")
    w("thread-writer-locks/.coordination.lock", "")
    w(f"thread-writer-locks/{TID}.lock", "")
    w("skills/example/SKILL.md", "---\nname: example\n---\n")
    w("plugins-cache/notes.txt", f"scratch {GH}\n")
    json.dump({"thread": TID, "archivedThread": TID2, "openai": OPENAI, "httpsCreds": HTTPS_CREDS},
              open(F/"Secrets/codex-values.json","w"), indent=2)

if __name__ == "__main__":
    write_codex_version_a()
    write_secret_corpus()
    write_claude_version_a()
    write_claude_malformed()
    print("fixtures regenerated; github token checksum-valid:", GH)
