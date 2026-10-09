# Apigee X Workforce Identity STS Token Exchange Proxy for BigQuery MCP

This Apigee X API proxy (`mcp-bq-sts-exchange`) offloads Google Cloud Security Token Service (STS) Workforce Identity Pool token exchange (`https://sts.googleapis.com/v1/token`) from your ADK Agent and routes authenticated Model Context Protocol (MCP) traffic to Google Cloud BigQuery (`https://bigquery.googleapis.com/mcp`).

---

## How It Works

1. **Request & Content-Type Validation (`AC-ValidateMcpRequest`, `JTP-ProtectMcpPayload`, `AC-ValidateAuthHeader`)**:
   - Validates allowed MCP Streamable HTTP verbs (`POST`, `GET`, `DELETE`), blocks path traversal sequences, enforces `Content-Type: application/json` + size limits prior to `JSONThreatProtection`, and verifies a single `Authorization: Bearer <token>` header (preventing HTTP Header Pollution).
2. **Zero-Leak Token Extraction (`EV-ExtractBearerToken`)**:
   - Extracts the incoming 3LO IdP JWT from `Authorization` into `private.idp_subject_token` (masked in Apigee Debug/Trace sessions).
3. **NIO-Thread Context & SHA-256 Cache Key Preparation (`AM-PrepareRequestAndCacheKey`)**:
   - Strips any client-spoofed `x-goog-user-project` or internal headers.
   - Reads Workforce Pool configuration in $O(1)$ from `apiproxy/resources/properties/sts.properties` (`{propertyset.sts.*}`) directly on the NIO thread.
   - Computes `{sha256Hex(private.idp_subject_token)}` so raw JWTs are never exposed as plaintext cache keys.
4. **L1/L2 Token Caching (`LC-LookupStsToken`, `PC-PopulateStsToken`)**:
   - Looks up `private.sts.access_token` in Apigee's cache keyed by `sts.workforce_pool_id`, `sts.workforce_provider_id`, `sts.user_project`, and `sts.subject_token_hash`.
5. **Conditional STS Token Exchange (`SC-ExchangeStsToken`, `AM-ExtractStsToken`)**:
   - On a cache miss (`lookupcache.LC-LookupStsToken.cachehit = false`), calls `https://sts.googleapis.com/v1/token` with `clearPayload="true"` on a dedicated `private.sts.request` message (preserving the original MCP JSON-RPC `request.content` payload for BigQuery) and extracts `$.access_token` into `private.sts.access_token`.
6. **Target Routing to BigQuery MCP (`AM-SetTargetStsAuth`)**:
   - Replaces `Authorization` with `Bearer {private.sts.access_token}`, sets `x-goog-user-project: {sts.user_project}`, and forwards the MCP request to `https://bigquery.googleapis.com/mcp`.

---

## 1. Configure `sts.properties`

Before deploying, update [`apiproxy/resources/properties/sts.properties`](file:///Users/gonzalezruben/Documents/sts-token-exchange/apiproxy/resources/properties/sts.properties) with your Workforce Identity Pool and Google Cloud Project values:

```properties
workforce_pool_id=YOUR_WORKFORCE_POOL_ID
workforce_provider_id=YOUR_WORKFORCE_PROVIDER_ID
user_project=YOUR_GOOGLE_CLOUD_PROJECT_ID
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
scope=https://www.googleapis.com/auth/cloud-platform
requested_token_type=urn:ietf:params:oauth:token-type:access_token
subject_token_type=urn:ietf:params:oauth:token-type:jwt
cache_ttl_sec=3000
```

*(Alternatively, you can provision an Environment-level `sts` PropertySet via the Apigee API so values are managed per environment without modifying the bundle.)*

---

## 2. Package & Deploy to Apigee X

```bash
# 1. Package the apiproxy bundle
zip -r mcp-bq-sts-exchange.zip apiproxy/

# 2. Upload the bundle to your Apigee X Organization
TOKEN=$(gcloud auth print-access-token)
ORG="YOUR_APIGEE_ORG"
ENV="YOUR_APIGEE_ENV"

curl -X POST \
  "https://apigee.googleapis.com/v1/organizations/${ORG}/apis?action=import&name=mcp-bq-sts-exchange" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@mcp-bq-sts-exchange.zip"

# 3. Deploy revision 1 to your target Apigee X Environment
curl -X POST \
  "https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/apis/mcp-bq-sts-exchange/revisions/1/deployments?override=true" \
  -H "Authorization: Bearer ${TOKEN}"
```

---

## 3. Simplified ADK Agent Code (Client-Side STS Exchange Removed)

With Apigee X handling the STS token exchange transparently on `/mcp`, your ADK agent no longer needs `WorkforceStsGcpAuthProvider`, `httpx`, `WORKFORCE_POOL_ID`, or `WORKFORCE_PROVIDER_ID`:

```python
import os

from google.adk.agents import Agent
from google.adk.auth.credential_manager import CredentialManager
from google.adk.integrations.agent_identity import GcpAuthProvider, GcpAuthProviderScheme
from google.adk.models.apigee_llm import ApigeeLlm
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams

PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")
AUTH_CONNECTOR = os.environ.get("AUTH_CONNECTOR")
APIGEE_HOST = os.environ.get("APIGEE_HOST")
AI_GATEWAY_PATH = "/ai-gateway"
CONTINUE_URI = os.environ.get("CONTINUE_URI")

# 1. Register the standard GcpAuthProvider (fetches 3LO IdP JWT from Agent Identity Auth Manager)
CredentialManager.register_auth_provider(GcpAuthProvider())

# 2. Define the Auth Manager connector scheme
auth_scheme = GcpAuthProviderScheme(
    name=f"projects/{PROJECT}/locations/{LOCATION}/connectors/{AUTH_CONNECTOR}",
    continue_uri=CONTINUE_URI,
)

system_instruction = (
    "You are a strict but helpful retail operations coordinator. "
    "Your goal is to help regional retail managers verify display compliance, analyze performance, and coordinate marketing materials.\n"
    "You must ONLY perform tasks that can be fulfilled by using the available tools:\n"
    "- getPlanogramV1StatusStoreId: Check compliance status for a store. Requires 'store_id'.\n"
    "- getAnalyticsV1FootTrafficStoreId: Get hourly foot traffic data. Requires 'store_id'.\n"
    "- postOrdersV1Signage: Submit an order for signage kits.\n"
    "Do not assume or offer capabilities beyond these tools.\n\n"
)

model = ApigeeLlm(
    model="apigee/gemini-3.1-flash-lite",
    proxy_url=f"https://{APIGEE_HOST}{AI_GATEWAY_PATH}",
)

# 3. Pass `auth_scheme` to McpToolset — attaches `Authorization: Bearer <idp_jwt>`
# and Apigee X exchanges it for a Workforce Identity Pool STS token before calling BigQuery.
mcp_tools = McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=f"https://{APIGEE_HOST}/mcp",
    ),
    auth_scheme=auth_scheme,
)

root_agent = Agent(
    model=model,
    name="merchandising_assistant_agent_authz",
    instruction=system_instruction,
    tools=[mcp_tools],
)

if __name__ == "__main__":
    print(f"Agent created: {root_agent.name}")
```
