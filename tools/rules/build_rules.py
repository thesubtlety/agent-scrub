#!/usr/bin/env python3
"""Builds Sources/SecretDetection/Resources/rules.json from the gitleaks default config (MIT, vendored in
tools/gitleaks/) plus History Guard's own rules in tools/rules/custom.json. Run after updating either input."""
import json, pathlib, re, tomllib, datetime

ROOT = pathlib.Path(__file__).resolve().parents[2]
GL = ROOT / "tools/gitleaks/gitleaks.toml"
CUSTOM = ROOT / "tools/rules/custom.json"
OUT = ROOT / "Sources/SecretDetection/Resources/rules.json"

# gitleaks rule id (prefix match) -> History Guard coarse kind. Everything else is vendorAPIKey.
KIND_BY_PREFIX = [
    ("github-", "githubToken"), ("aws-access-token", "awsAccessKeyID"), ("stripe-", "stripeKey"),
    ("slack-", "slackToken"), ("openai-", "openAIKey"), ("anthropic-", "anthropicKey"),
    ("gcp-api-key", "googleAPIKey"), ("private-key", "privateKey"), ("jwt", "jwt"),
    ("generic-api-key", "genericSecret"),
]
# A bare AWS access key ID (AKIA…) is an identifier, not a secret — don't flag it at all. The AWS secret
# access key (the thing that matters) is detected by a separate custom rule.
# The gitleaks huggingface rules only allow `[a-z]` after the prefix, so real tokens containing digits are
# missed; replaced by corrected custom rules (hf_ / api_org_ with [a-zA-Z0-9]).
SKIP_RULES = {"aws-access-token", "huggingface-access-token", "huggingface-organization-api-token"}
CONFIDENCE_BY_KIND: dict[str, str] = {}
MASK_BY_KIND = {
    "githubToken": (4, 4), "awsAccessKeyID": (4, 4), "stripeKey": (8, 4), "slackToken": (5, 4),
    "openAIKey": (3, 4), "anthropicKey": (7, 4), "googleAPIKey": (4, 4), "privateKey": (0, 0),
    "jwt": (3, 4), "genericSecret": (0, 3), "vendorAPIKey": (4, 4),
}
ACRONYMS = {"api": "API", "aws": "AWS", "gcp": "GCP", "jwt": "JWT", "url": "URL", "id": "ID", "pat": "PAT",
            "ssh": "SSH", "oauth": "OAuth", "github": "GitHub", "gitlab": "GitLab", "openai": "OpenAI", "pkcs12": "PKCS#12",
            "hashicorp": "HashiCorp", "tf": "Terraform", "sendgrid": "SendGrid", "mailgun": "Mailgun", "npm": "npm",
            "pypi": "PyPI", "ibm": "IBM", "iam": "IAM", "sas": "SAS", "hmac": "HMAC", "ip": "IP", "sso": "SSO",
            "cli": "CLI", "db": "DB", "sql": "SQL", "http": "HTTP", "smtp": "SMTP", "oidc": "OIDC", "saml": "SAML",
            "jenkins": "Jenkins", "docker": "Docker", "postgres": "Postgres", "mongodb": "MongoDB"}

def swift_compatible(pattern: str) -> str:
    """RE2 -> Swift Regex syntax shims. Swift rejects bare '{' or '}' inside a character class."""
    out, in_class, i = [], False, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2]); i += 2; continue
        if not in_class and c == "[":
            in_class = True
            out.append(c)
            # a ']' or '^]' right after the opening bracket is literal
            if i + 1 < len(pattern) and pattern[i + 1] == "^":
                out.append("^"); i += 1
            if i + 1 < len(pattern) and pattern[i + 1] == "]":
                out.append("\\]"); i += 1
            i += 1; continue
        if in_class and c == "]":
            in_class = False
        elif in_class and c in "{}":
            out.append("\\" + c); i += 1; continue
        out.append(c); i += 1
    return "".join(out)

LAZY_PREFIX = "[\\w.-]{0,50}?"
FORCE_ANCHORED = {"generic-api-key"}

def strip_identifier_prefix(pattern: str) -> tuple[bool, str]:
    """Removes gitleaks' leading lazy identifier prefix in its two shapes:
    '(?i)[\\w.-]{0,50}?...' and '[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?...'. The prefix only widens the match to
    include the variable name; Swift's backtracking engine retries it at every byte."""
    changed = False
    if pattern.startswith("(?i)" + LAZY_PREFIX):
        pattern = "(?i)" + pattern[len("(?i)" + LAZY_PREFIX):]; changed = True
    if pattern.startswith(LAZY_PREFIX):
        pattern = pattern[len(LAZY_PREFIX):]; changed = True
    if pattern.startswith("(?i:" + LAZY_PREFIX):
        pattern = "(?i:" + pattern[len("(?i:" + LAZY_PREFIX):]; changed = True
    return changed, pattern

def leading_group(pattern: str) -> str:
    """Text of the first parenthesised group (after optional inline flags)."""
    i = 0
    if pattern.startswith("(?i)"): i = 4
    if i >= len(pattern) or pattern[i] != "(": return ""
    depth, j = 0, i
    while j < len(pattern):
        c = pattern[j]
        if c == "\\": j += 2; continue
        if c == "(": depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0: return pattern[i:j + 1]
        j += 1
    return ""

def anchors_align_with_leading_group(pattern: str, anchors: list[str]) -> bool:
    lead = leading_group(pattern).lower()
    if not lead: return False
    # The leading group must be the keyword alternation, not a wrapper that also swallows later parts: for the
    # (?i:(?:kw)(?:tail)...) shape the whole thing is one group, which is still fine because it starts at the keyword.
    return all(a.lower().replace("_", "_") in lead for a in anchors)

def max_match_length(pattern: str) -> int | None:
    """Crude upper bound on match length: sums every atom's maximum, treating alternation as a sum (over-estimate,
    hence safe). None when any quantifier is unbounded."""
    i, n = 0, len(pattern)
    total = 0
    last_atom = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            if i - 1 < n and pattern[i - 1] in "xu":
                # \xHH / \uHHHH escapes
                while i < n and pattern[i] in "0123456789abcdefABCDEF" and (i - 2) < 6: i += 1
            last_atom = 1; total += 1; continue
        if c == "[":
            depth = 1; i += 1
            if i < n and pattern[i] == "^": i += 1
            if i < n and pattern[i] == "]": i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\": i += 1
                i += 1
            i += 1
            last_atom = 1; total += 1; continue
        if c == "{":
            j = pattern.find("}", i)
            body = pattern[i + 1:j]
            if "," in body:
                lo, hi = body.split(",", 1)
                if hi.strip() == "": return None
                mult = int(hi)
            else:
                mult = int(body)
            total += last_atom * (mult - 1)
            last_atom *= mult
            i = j + 1
            if i < n and pattern[i] == "?": i += 1
            continue
        if c in "+*":
            return None
        if c == "?":
            i += 1; continue
        if c == "(":
            # skip group syntax like (?i: or (?<name>
            i += 1
            if i < n and pattern[i] == "?":
                while i < n and pattern[i] not in ":)" and pattern[i] != ">": i += 1
                i += 1
            continue
        if c in ")|^$":
            i += 1; continue
        last_atom = 1; total += 1; i += 1
    return total

def label_for(rule_id: str) -> str:
    return " ".join(ACRONYMS.get(w, w.capitalize()) for w in rule_id.split("-"))

def kind_for(rule_id: str) -> str:
    for prefix, kind in KIND_BY_PREFIX:
        if rule_id.startswith(prefix):
            return kind
    return "vendorAPIKey"

def convert_allowlist(a: dict) -> dict | None:
    if a.get("paths") or a.get("commits"):
        # Path/commit conditions describe repository layouts, which do not exist in agent history. An AND
        # allowlist that depends on them can never be satisfied here; an OR one still applies its regexes/stopwords.
        if a.get("condition", "OR").upper() == "AND":
            return None
    if not a.get("regexes") and not a.get("stopwords"):
        return None
    return {
        "target": a.get("regexTarget", "secret") or "secret",
        "condition": a.get("condition", "OR").upper(),
        "regexes": [swift_compatible(x) for x in a.get("regexes", [])],
        "stopwords": [s.lower() for s in a.get("stopwords", [])],
    }

def main() -> None:
    gl = tomllib.load(GL.open("rb"))
    custom = json.loads(CUSTOM.read_text())
    rules, skipped = [], []
    for r in gl["rules"]:
        rid = r["id"]
        if rid in SKIP_RULES:
            skipped.append((rid, "intentionally disabled")); continue
        if "regex" not in r:
            skipped.append((rid, "no regex")); continue
        if r.get("path"):
            skipped.append((rid, "path-conditioned")); continue
        kind = kind_for(rid)
        out = {
            "id": f"gitleaks:{rid}", "source": "gitleaks", "label": label_for(rid),
            "description": r.get("description", ""), "kind": kind,
            "confidence": CONFIDENCE_BY_KIND.get(kind, "medium" if kind == "genericSecret" else "high"),
            "pattern": swift_compatible(r["regex"]),
            "anchors": [k.lower() for k in r.get("keywords", [])],
            "window": {"before": 128, "after": 4096},
            "mask": dict(zip(("prefix", "suffix"), MASK_BY_KIND[kind])),
        }
        if "entropy" in r: out["minEntropy"] = float(r["entropy"])
        if "secretGroup" in r: out["secretGroup"] = int(r["secretGroup"])
        if rid == "private-key":
            out.update(canonicalizer="pem", multiline=True, window={"before": 32, "after": 32768})
        if rid.startswith("jwt"):
            out["window"] = {"before": 8, "after": 8192}
        stripped, pat = strip_identifier_prefix(out["pattern"])
        if stripped:
            # Keyword, optional identifier tail, separator, secret group. Start at the keyword and require a
            # separator shortly after it; the secret group is unchanged.
            out["pattern"] = pat
            if rid != "generic-api-key":
                out.update(requireNear={"chars": "=:>|?,", "within": 80})
            # When every anchor is a literal inside the leading keyword group, an anchor hit is exactly where the
            # regex must start, so the scanner can anchor it with ^ and run it once per hit.
            # generic-api-key spells "password" as passw(?:or)?d, so the literal check fails; its keywords are
            # verified by hand to be exactly the leading alternation.
            if rid in FORCE_ANCHORED or anchors_align_with_leading_group(pat, out["anchors"]):
                out["anchoredAtHit"] = True
        bound = max_match_length(out["pattern"])
        out["window"] = {"before": 8 if stripped else 128, "after": min(4096, bound + 32) if bound is not None else 4096}
        if rid == "generic-api-key":
            # gitleaks starts this regex with a lazy 0-50 char identifier prefix so the match shows the variable
            # name. Swift's engine then retries the alternation at every byte. The secret group is unchanged if
            # we start at the keyword instead, which is where the anchor hit is anyway.
            out["pattern"] = re.sub(r"^\(\?i\)\[\\w\.-\]\{0,50\}\?", "(?i)", out["pattern"], count=1)
            assert not out["pattern"].startswith("(?i)[\\w.-]"), out["pattern"][:40]
            out.update(layer="keyed", requireNear={"chars": "=:>|?,", "within": 40}, window={"before": 8, "after": 400})
        if rid in ("github-pat", "github-oauth", "github-app-token", "github-refresh-token"):
            out["validator"] = "github-crc32"
        als = [convert_allowlist(a) for a in (r.get("allowlists") or ([r["allowlist"]] if r.get("allowlist") else []))]
        als = [a for a in als if a]
        if als: out["allowlists"] = als
        if rid == "private-key":
            # Docs and stubs embed a bare PEM header around prose ("See the docs for how to generate one."); the
            # lazy body can span it to a later footer. Real key material is continuous base64 — it never contains
            # spaced lowercase words, so a run of three rejects the prose without touching genuine keys.
            out.setdefault("allowlists", []).append({
                "target": "match", "condition": "OR",
                "regexes": ["[a-z]{2,}\\s+[a-z]{2,}\\s+[a-z]{2,}"], "stopwords": [],
            })
        rules.append(out)
    for r in custom["rules"]:
        rules.append(r)
    ga = gl.get("allowlist", {})
    global_allow = [{"target": ga.get("regexTarget", "secret") or "secret", "condition": "OR",
                     "regexes": [swift_compatible(x) for x in ga.get("regexes", [])], "stopwords": [s.lower() for s in ga.get("stopwords", [])]}]
    doc = {
        "version": 2,
        "sources": {"gitleaks": {"license": "MIT", "path": "tools/gitleaks/gitleaks.toml",
                                 "built": datetime.date.today().isoformat(), "rules": len([r for r in rules if r["source"] == "gitleaks"]),
                                 "skipped": skipped},
                    "custom": {"path": "tools/rules/custom.json", "rules": len(custom["rules"])}},
        "placeholders": custom["placeholders"],
        "globalAllowlists": global_allow,
        "rules": rules,
    }
    OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rules)} rules ({len(skipped)} gitleaks rules skipped: {skipped})")

if __name__ == "__main__":
    main()
