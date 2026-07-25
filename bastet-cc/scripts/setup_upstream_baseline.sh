#!/usr/bin/env bash
# Stand up upstream Bastet as a reproducible baseline, pointed at the AIS3 LLM gateway.
#
# Upstream's README walks nine manual browser steps: create an owner account, click
# through to Settings, mint an API key, create an OpenAI credential, copy its ID back
# into .env, then import. None of that is scriptable as written, which makes the
# baseline impossible to reproduce byte-for-byte across machines. Everything here goes
# through n8n's REST API instead, so the control group can be rebuilt from zero.
#
# Two upstream defects are worked around, both reported in the writeup:
#   1. erc4626.json and flashloan.json ship identical webhookIds (flashloan is a
#      copy-paste of erc4626), so only one of the two can ever be active. Out of the
#      box that means 8 of 9 workflows run.
#   2. OPENAI_MODEL_NAME silently overrides whatever model the workflow JSON declares,
#      but it appears in no documentation and not in .env.example.
#
# Usage:  ./setup_baseline.sh [model]
set -euo pipefail

MODEL="${1:-ais3/llama-3.3-70b}"
BASE_URL="${AIS3_BASE_URL:-https://llm-api.zoolab.org/v1}"
API_KEY="${AIS3_API_KEY:?set AIS3_API_KEY}"
N8N="http://localhost:5678"
OWNER_EMAIL="team_011@ais3.org"
OWNER_PASS="${N8N_OWNER_PASS:-changeme-local-only}"
COOKIES="$(mktemp)"
cd "$(dirname "$0")"

echo "==> Resetting n8n and postgres"
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d >/dev/null

echo "==> Waiting for n8n"
# curl's own retry is the only portable way to pace this: a bare shell loop spins
# through every attempt in milliseconds because a refused connection returns at once.
curl -s -o /dev/null --retry 60 --retry-delay 2 --retry-connrefused --retry-all-errors \
  --max-time 240 "$N8N/rest/settings"

echo "==> Creating owner"
# n8n answers /rest/settings before migrations finish, and until they do the setup route
# replies "n8n is starting up" with HTTP 200 -- so curl's retry cannot see the failure and
# a bare shell loop burns all its attempts in milliseconds. Pace it explicitly instead.
resp=""
for _ in $(seq 1 60); do
  resp=$(curl -s -X POST "$N8N/rest/owner/setup" -H 'Content-Type: application/json' \
    -c "$COOKIES" \
    -d "{\"email\":\"$OWNER_EMAIL\",\"firstName\":\"AIS3\",\"lastName\":\"Team011\",\"password\":\"$OWNER_PASS\"}")
  case "$resp" in
    *'"data"'*) break ;;
  esac
  python3 -c 'import time; time.sleep(3)'
done
case "$resp" in
  *'"data"'*) ;;
  *) echo "    owner setup failed: ${resp:0:200}" >&2; exit 1 ;;
esac
echo "$resp" | python3 -c "import json,sys;print('    owner:',json.load(sys.stdin)['data']['email'])"

echo "==> Minting n8n API key"
N8N_KEY=$(curl -s -b "$COOKIES" -X POST "$N8N/rest/api-keys" -H 'Content-Type: application/json' \
  -d '{"label":"Bastet","expiresAt":null,"scopes":["workflow:create","workflow:read","workflow:update","workflow:list","workflow:activate","workflow:deactivate","workflow:delete","execution:read","execution:list","credential:create"]}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['rawApiKey'])")

echo "==> Creating OpenAI-compatible credential -> $BASE_URL"
CRED_ID=$(curl -s -b "$COOKIES" -X POST "$N8N/rest/credentials" -H 'Content-Type: application/json' \
  -d "{\"name\":\"ais3-zoolab\",\"type\":\"openAiApi\",\"data\":{\"apiKey\":\"$API_KEY\",\"url\":\"$BASE_URL\"}}" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])")
echo "    credential: $CRED_ID"

echo "==> Writing .env"
cat > .env <<ENVEOF
POSTGRES_USER=bastet
POSTGRES_PASSWORD=bastet
POSTGRES_DB=n8n
POSTGRES_NON_ROOT_USER=test
POSTGRES_NON_ROOT_PASSWORD=test

N8N_API_BASE_URL=$N8N
N8N_API_KEY=$N8N_KEY
N8N_OPENAI_CREDENTIAL_ID=$CRED_ID

ETHERSCAN_API_KEY=unused

# Undocumented upstream hook: overrides the model declared in every workflow JSON.
OPENAI_MODEL_NAME=$MODEL
ENVEOF

echo "==> Repairing duplicated webhookIds (upstream: flashloan == erc4626)"
python3 - <<'PYEOF'
import json, uuid
path = "n8n_workflow/flashloan.json"
doc = json.load(open(path))
for node in doc["nodes"]:
    if node.get("webhookId"):
        fresh = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"bastet-flashloan-{node['name']}"))
        node["webhookId"] = fresh
        if node["type"] == "n8n-nodes-base.webhook":
            node["parameters"]["path"] = fresh
json.dump(doc, open(path, "w"), indent=2)
PYEOF

echo "==> Importing workflows"
echo "all" | PYTHONPATH=cli .venv/bin/python cli/main.py init 2>&1 | grep -E '✅|❌' || true

echo "==> Verifying"
PYTHONPATH=cli .venv/bin/python - <<'PYEOF'
import re, requests
key = re.search(r'^N8N_API_KEY=(.*)$', open('.env').read(), re.M).group(1).strip()
h = {"X-N8N-API-KEY": key}
base = "http://localhost:5678/api/v1"
wfs = requests.get(f"{base}/workflows?limit=50", headers=h).json()["data"]
models, active = set(), 0
for w in wfs:
    active += bool(w["active"])
    full = requests.get(f"{base}/workflows/{w['id']}", headers=h).json()
    for n in full["nodes"]:
        if "lmChatOpenAi" in n["type"]:
            models.add(n["parameters"]["model"]["value"])
print(f"    active: {active}/{len(wfs)}")
print(f"    models: {sorted(models)}")
PYEOF
rm -f "$COOKIES"
echo "==> Baseline ready at $N8N"
