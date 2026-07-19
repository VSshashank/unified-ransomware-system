# SH Integration & DevOps Documentation

## Unified Ransomware Detection & Recovery System

This document explains the work completed for the SH role in the URDS college capstone project. It is written for presentation preparation, so it explains what was built, why it was built, how the files are organized, what each important file does, and how to run and demonstrate the system.

---

## 1. Role Summary

My role is **SH - Integration & DevOps Lead**.

The project is a microservices-based ransomware detection and recovery platform. The complete system has these main parts:

- Monitor Service
- ML Engine Service
- Ledger Service
- Response Service
- API Gateway
- Streamlit Dashboard
- Docker Compose orchestration

The teammate-owned services are:

- Monitor logic
- ML detection/classification logic
- Ledger/blockchain logic
- Response/recovery logic

My responsibility is not to implement the internal business logic of those services. My responsibility is to connect them together through:

- A central API Gateway
- A live dashboard
- Docker-based one-command startup
- API documentation
- Integration tests
- Temporary stub services so the system can run before teammate logic is complete

---

## 2. What I Implemented

I implemented the SH-owned integration layer for Weeks 1-16:

1. **API Gateway**
   - Built using FastAPI.
   - Runs on port `8000`.
   - Provides a single entry point for the dashboard and external clients.
   - Routes requests to Monitor, ML Engine, Ledger, and Response services.
   - Implements JWT authentication.
   - Implements role/tier-based rate limiting.
   - Normalizes errors into one standard JSON format.
   - Implements the composite `/analyze` workflow.

2. **Dashboard v1**
   - Built using Streamlit.
   - Runs on port `8501`.
   - Shows live file events, entropy chart, threat banner, model metrics, system health, and latest ledger block.
   - Refreshes approximately every second.

3. **Docker Compose Setup**
   - Starts all six services with one command.
   - Places all services on a shared Docker network called `ransomware_net`.
   - Adds healthchecks for each service.

4. **Stub Backend Services**
   - Added temporary placeholder services for Monitor, ML Engine, Ledger, and Response.
   - These stubs return realistic fake data that matches the required API contracts.
   - They are clearly marked as placeholders and can be replaced later by teammates.

5. **OpenAPI Documentation**
   - Added a full OpenAPI 3.0 specification for the gateway.
   - Documents all gateway endpoints, request schemas, response schemas, JWT auth, and standard error format.

6. **Gateway Tests**
   - Added pytest tests for authentication, rate limiting, proxy behavior, and the `/analyze` flow.

---

## 3. High-Level Architecture

The user or dashboard does not directly call each backend service. Instead, everything goes through the API Gateway.

```text
User / Dashboard
       |
       v
API Gateway :8000
       |
       +--> Monitor Service :8001
       |
       +--> ML Engine Service :8002
       |
       +--> Ledger Service :8003
       |
       +--> Response Service :8004

Dashboard :8501 reads data from Gateway :8000
```

The gateway is the central integration point. This is important because:

- Authentication is handled in one place.
- Rate limiting is handled in one place.
- The dashboard only needs to know one backend URL.
- Internal services can change as long as their contracts remain stable.
- Integration testing becomes easier.

---

## 4. Folder Structure Added or Updated

```text
Unified-randsomware-system/
├── .env.example
├── .gitignore
├── README.md
├── docker-compose.yml
├── docs/
│   ├── api_spec.md
│   ├── SH_INTEGRATION_PRESENTATION_NOTES.md
│   └── openapi/
│       └── gateway.yaml
└── services/
    ├── gateway/
    │   ├── Dockerfile
    │   ├── auth.py
    │   ├── main.py
    │   ├── models.py
    │   ├── rate_limit.py
    │   ├── requirements.txt
    │   ├── routers/
    │   │   ├── __init__.py
    │   │   ├── ledger.py
    │   │   ├── ml.py
    │   │   ├── monitor.py
    │   │   ├── proxy.py
    │   │   └── response.py
    │   └── tests/
    │       └── test_gateway.py
    ├── dashboard/
    │   ├── Dockerfile
    │   ├── app.py
    │   └── requirements.txt
    ├── monitor/
    │   ├── Dockerfile
    │   ├── app.py
    │   └── requirements.txt
    ├── ml-engine/
    │   ├── Dockerfile
    │   ├── app.py
    │   └── requirements.txt
    ├── ledger/
    │   ├── Dockerfile
    │   ├── app.py
    │   └── requirements.txt
    └── response/
        ├── Dockerfile
        ├── app.py
        └── requirements.txt
```

Important note: the existing repo already had the ML folder named `services/ml-engine`, so I kept that folder name instead of creating a duplicate `services/ml_engine`. In Docker Compose, the service is still named `ml_engine`, so the gateway can call it using:

```text
http://ml_engine:8002
```

---

## 5. Root-Level Files

### 5.1 `.env.example`

Purpose:

- Provides environment variables needed for local Docker setup.
- Should be copied to `.env` before running the system.

Important values:

```env
JWT_SECRET=dev-only-change-me
JWT_ALGORITHM=HS256
MONITOR_URL=http://monitor:8001
ML_URL=http://ml_engine:8002
LEDGER_URL=http://ledger:8003
RESPONSE_URL=http://response:8004
GATEWAY_URL=http://gateway:8000
```

Explanation:

- `JWT_SECRET` is used by the gateway to sign and verify local development tokens.
- `MONITOR_URL`, `ML_URL`, `LEDGER_URL`, and `RESPONSE_URL` tell the gateway where the internal services are.
- `GATEWAY_URL` tells the dashboard where to send API requests.

Presentation point:

> This file makes the system configurable, so services can be moved or replaced without changing source code.

---

### 5.2 `.gitignore`

Purpose:

- Prevents local, generated, and sensitive files from being committed.

Examples of ignored files:

- `.env`
- Python cache files
- virtual environments
- logs
- local models
- watched files
- `.DS_Store`

Presentation point:

> This keeps the repository clean and prevents environment secrets or generated files from entering version control.

---

### 5.3 `README.md`

Purpose:

- Gives setup and usage instructions.
- Documents branch naming conventions.
- Documents conventional commit examples.
- Explains how to replace stub services with real teammate implementations.

Important commands from README:

```bash
cp .env.example .env
docker compose up -d --build
```

Presentation point:

> The README allows a fresh clone of the project to be started with one main command after copying the environment file.

---

### 5.4 `docker-compose.yml`

Purpose:

- Defines and runs the complete six-service system.

Services included:

| Service | Port | Purpose |
|---|---:|---|
| monitor | 8001 | File monitoring stub |
| ml_engine | 8002 | ML prediction stub |
| ledger | 8003 | Ledger/hash-chain stub |
| response | 8004 | Recovery/response stub |
| gateway | 8000 | Central API gateway |
| dashboard | 8501 | Streamlit UI |

Each service has:

- Build context
- Container name
- Port mapping
- Restart policy
- Network configuration
- Healthcheck

Example from Compose:

```yaml
gateway:
  build: ./services/gateway
  ports:
    - "8000:8000"
  environment:
    - MONITOR_URL=http://monitor:8001
    - ML_URL=http://ml_engine:8002
    - LEDGER_URL=http://ledger:8003
    - RESPONSE_URL=http://response:8004
```

Explanation:

- The gateway container communicates with other containers using Docker service names.
- The host machine can access the gateway at `localhost:8000`.
- The host machine can access the dashboard at `localhost:8501`.

Presentation point:

> Docker Compose turns the project from several separate services into a single runnable system.

---

## 6. OpenAPI Specification

File:

```text
docs/openapi/gateway.yaml
```

Purpose:

- Defines the official API contract for the gateway.
- Documents request and response shapes.
- Documents JWT bearer authentication.
- Documents the standard error response.

Main routes documented:

```text
GET  /health
POST /auth/token
POST /monitor/start
POST /monitor/stop
GET  /monitor/status
GET  /monitor/events
POST /predict
GET  /model/metrics
POST /ledger/log
GET  /ledger/entries
POST /response/terminate
POST /response/isolate
POST /response/recover
POST /response/trigger
POST /analyze
```

Standard error response:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "timestamp": "2026-01-31T10:05:00Z",
    "request_id": "req_abc123"
  },
  "details": {}
}
```

Presentation point:

> The OpenAPI file is useful because all teammates can agree on request and response formats before implementing internal service logic.

---

## 7. API Gateway Explanation

The gateway is located in:

```text
services/gateway/
```

It is built with:

- FastAPI
- Uvicorn
- Pydantic
- httpx
- python-jose
- pytest

---

### 7.1 `services/gateway/main.py`

Purpose:

- Main FastAPI application entry point.
- Registers all gateway routers.
- Adds request IDs.
- Handles standard error formatting.
- Provides `/health`.
- Provides `/auth/token`.
- Implements `/analyze`.

Important responsibilities:

1. Create FastAPI app:

```python
app = FastAPI(title="URDS API Gateway", version="1.0.0")
```

2. Register routers:

```python
app.include_router(monitor.router)
app.include_router(ml.router)
app.include_router(ledger.router)
app.include_router(response.router)
```

This separates routes by service area so gateway code stays organized.

3. Add request ID middleware:

```python
request.state.request_id = request.headers.get("X-Request-ID", f"req_{uuid4().hex[:12]}")
```

Every request gets a unique request ID. This ID is also returned in error responses.

Why this matters:

- Easier debugging
- Easier log tracing
- Better production-style API behavior

4. Standard error handler:

The gateway catches validation errors, HTTP errors, and unexpected errors, then converts them into the standard error response format.

Example:

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Missing bearer token",
    "timestamp": "...",
    "request_id": "req_..."
  },
  "details": {}
}
```

5. `/health`

This endpoint is unauthenticated.

It checks:

- Gateway itself
- Monitor
- ML Engine
- Ledger
- Response

If all services are healthy, it returns:

```json
{
  "status": "healthy",
  "services": {
    "gateway": {"status": "healthy"},
    "monitor": {"status": "healthy"},
    "ml_engine": {"status": "healthy"},
    "ledger": {"status": "healthy"},
    "response": {"status": "healthy"}
  }
}
```

6. `/auth/token`

This is a development-only endpoint.

It generates a JWT token so the gateway can be tested without building a full login system.

Example request:

```json
{
  "sub": "user_id_123",
  "role": "admin",
  "tier": "enterprise"
}
```

Example response:

```json
{
  "access_token": "...",
  "token_type": "bearer"
}
```

7. `/analyze`

This is the main composite workflow.

Flow:

```text
Client sends file path
        |
        v
Gateway calls Monitor /features
        |
        v
Gateway sends features to ML /predict
        |
        v
Gateway logs result to Ledger /ledger/log
        |
        v
Gateway returns prediction
```

Why this is important:

> `/analyze` proves that the gateway can orchestrate multiple backend services in sequence, not just forward single requests.

---

### 7.2 `services/gateway/auth.py`

Purpose:

- Handles JWT creation and validation.

Important functions:

```python
create_access_token(...)
```

Creates a signed JWT with:

- `sub`
- `role`
- `tier`
- `iat`
- `exp`

```python
decode_token(...)
```

Validates the JWT using:

- `JWT_SECRET`
- `JWT_ALGORITHM`

```python
get_current_user(...)
```

FastAPI dependency that checks the `Authorization` header.

Expected header:

```text
Authorization: Bearer <token>
```

If the token is missing or invalid, it raises a `401 Unauthorized` error.

Presentation point:

> Authentication is centralized in the gateway, so backend services do not each need their own authentication logic during integration.

---

### 7.3 `services/gateway/rate_limit.py`

Purpose:

- Enforces tiered request limits.

Configured tiers:

| Tier | Requests/min | Burst |
|---|---:|---:|
| Free | 60 | 100 |
| Premium | 300 | 500 |
| Enterprise | 1000 | 2000 |

How tier is selected:

1. First check the JWT `tier` claim.
2. If not present, check the JWT `role`.
3. Unknown roles default to Free.

Examples:

```text
admin      -> enterprise
enterprise -> enterprise
premium    -> premium
free       -> free
unknown    -> free
```

Implementation:

- Uses an in-memory token bucket.
- Each user gets a bucket based on `sub` and tier.
- Requests consume tokens.
- Tokens refill over time.

When limit is exceeded:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Free tier rate limit exceeded",
    "timestamp": "...",
    "request_id": "req_..."
  },
  "details": {
    "tier": "free",
    "requests_per_minute": 60,
    "burst": 100
  }
}
```

Presentation point:

> Rate limiting protects the gateway from abuse and simulates production API tier behavior.

---

### 7.4 `services/gateway/models.py`

Purpose:

- Defines request models using Pydantic.

Important models:

- `TokenRequest`
- `TokenResponse`
- `MonitorStartRequest`
- `AnalyzeRequest`
- `PredictRequest`
- `LedgerLogRequest`
- `TerminateRequest`
- `IsolateRequest`
- `RecoverRequest`
- `TriggerRequest`

Why models are useful:

- Validate incoming JSON.
- Make code easier to understand.
- Help keep request payloads consistent with the OpenAPI contract.

Example:

```python
class AnalyzeRequest(BaseModel):
    file_path: str
```

This means `/analyze` expects:

```json
{
  "file_path": "/path/to/file.doc"
}
```

---

### 7.5 `services/gateway/routers/proxy.py`

Purpose:

- Shared helper for calling downstream services.

It reads service URLs:

```python
MONITOR_URL = os.getenv("MONITOR_URL", "http://localhost:8001")
ML_URL = os.getenv("ML_URL", "http://localhost:8002")
LEDGER_URL = os.getenv("LEDGER_URL", "http://localhost:8003")
RESPONSE_URL = os.getenv("RESPONSE_URL", "http://localhost:8004")
```

Important function:

```python
call_downstream(...)
```

Uses `httpx.AsyncClient` to call another service.

If a downstream service is unavailable, the gateway returns a `503 Service Unavailable` error.

Presentation point:

> This file prevents repeated HTTP forwarding code in every router.

---

### 7.6 Gateway Router Files

The gateway routes are separated by backend service.

#### `routers/monitor.py`

Routes:

```text
POST /monitor/start
POST /monitor/stop
GET  /monitor/status
GET  /monitor/events
```

These routes forward requests to the Monitor service.

#### `routers/ml.py`

Routes:

```text
POST /predict
GET  /model/metrics
```

These routes forward requests to the ML Engine.

#### `routers/ledger.py`

Routes:

```text
POST /ledger/log
GET  /ledger/entries
```

These routes forward requests to the Ledger service.

#### `routers/response.py`

Routes:

```text
POST /response/terminate
POST /response/isolate
POST /response/recover
POST /response/trigger
```

These routes forward requests to the Response service.

All router routes are protected by:

- JWT authentication
- Rate limiting

Presentation point:

> Separating routers by service keeps the gateway maintainable as the API grows.

---

## 8. Dashboard Explanation

The dashboard is located in:

```text
services/dashboard/
```

It is built with:

- Streamlit
- Plotly
- Pandas
- Requests
- streamlit-autorefresh

The dashboard was redesigned to be easier to explain during a presentation. Instead of showing only raw metrics, it now presents the system as an operations view:

- A top-level security banner explains whether the latest event is safe or suspicious.
- An end-to-end pipeline row shows Monitor, ML Engine, Ledger, and Response status in order.
- A current-event panel explains which file is being reviewed.
- A model-decision panel shows prediction, confidence, threat level, and the strongest signals.
- An entropy trend chart shows recent file entropy with a high-risk threshold line.
- A ledger evidence panel shows the latest tamper-proof block information.
- Detailed service health, recent file events, and model-quality tables are kept lower on the page.

Presentation point:

> The improved dashboard tells the story of what is happening: a file event is captured, the ML engine classifies it, the ledger records evidence, and the response service is ready for action.

---

### 8.1 `services/dashboard/app.py`

Purpose:

- Provides a browser-based visual dashboard for the system.

Main features:

1. Auto-refresh every second:

```python
st_autorefresh(interval=1000, key="urds_refresh")
```

2. Creates a development JWT token:

```python
make_dashboard_token()
```

This allows the dashboard to call protected gateway endpoints.

3. Calls gateway endpoints:

```text
GET /health
GET /monitor/status
GET /monitor/events
GET /model/metrics
GET /ledger/entries
POST /predict
```

4. Displays a threat banner:

```text
System Secure
```

or

```text
Threat Detected
```

The banner color changes based on the latest prediction.

5. Displays system metrics:

- Gateway status
- Files monitored
- Events captured
- Uptime seconds

6. Displays live file events:

- Timestamp
- Event type
- File path
- Entropy
- Process ID
- User

7. Displays entropy chart:

- Uses Plotly line chart.
- Shows entropy over time.
- Helps visualize suspicious file behavior.

8. Displays ML metrics:

- Accuracy
- Precision
- Recall
- F1 score
- Last trained timestamp

9. Displays latest ledger block:

- Block ID
- Current hash
- Previous hash
- Tamper-proof status
- Timestamp

Presentation point:

> The dashboard gives a real-time operational view of ransomware monitoring, prediction, and ledger activity through the gateway.

---

## 9. Stub Service Explanation

The stubs exist because teammates are responsible for the real internal service logic. These stubs make it possible to test the gateway and dashboard immediately.

Each stub:

- Runs as a FastAPI service.
- Has a Dockerfile.
- Has a requirements file.
- Returns realistic JSON matching the contract.
- Is clearly marked as a placeholder.

---

### 9.1 Monitor Stub

File:

```text
services/monitor/app.py
```

Runs on:

```text
8001
```

Routes:

```text
GET  /health
POST /monitor/start
POST /monitor/stop
GET  /monitor/status
GET  /monitor/events
POST /features
```

Purpose:

- Simulates file monitoring.
- Generates fake file events.
- Returns feature data for `/analyze`.

Example event:

```json
{
  "event_id": "evt_abc123",
  "file_path": "/watch/capstone_file_10.doc",
  "event_type": "modified",
  "entropy": 7.89,
  "timestamp": "2026-01-31T10:00:00Z",
  "process_id": 4512,
  "user": "admin"
}
```

Important behavior:

- `/monitor/status` returns files monitored, events captured, and uptime.
- `/monitor/events` generates and returns recent fake events.
- `/features` returns a feature dictionary used by the gateway `/analyze` route.

Presentation point:

> The Monitor stub simulates file activity so the dashboard can show live data before the real monitor service is ready.

---

### 9.2 ML Engine Stub

File:

```text
services/ml-engine/app.py
```

Runs on:

```text
8002
```

Routes:

```text
GET  /health
POST /predict
GET  /model/metrics
```

Purpose:

- Simulates ML classification.
- Uses a simple heuristic based on entropy, modification rate, and crypto API calls.

Example request:

```json
{
  "features": {
    "shannon_entropy": 7.89,
    "file_size": 1048576,
    "magic_bytes": "4D5A",
    "modification_rate": 0.85,
    "pe_imports_count": 45,
    "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"]
  }
}
```

Example response:

```json
{
  "prediction": "ransomware",
  "confidence": 0.94,
  "model_version": "1.0.0",
  "timestamp": "2026-01-31T10:01:05Z",
  "threat_level": "high",
  "features_importance": {
    "shannon_entropy": 0.35,
    "modification_rate": 0.28,
    "api_calls": 0.22
  }
}
```

Presentation point:

> The ML stub does not replace the final model. It only allows the gateway and dashboard to be tested with realistic prediction data.

---

### 9.3 Ledger Stub

File:

```text
services/ledger/app.py
```

Runs on:

```text
8003
```

Routes:

```text
GET  /health
POST /ledger/log
GET  /ledger/entries
```

Purpose:

- Simulates event logging.
- Creates an in-memory hash chain.

Example ledger response:

```json
{
  "block_id": 42,
  "current_hash": "a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2",
  "previous_hash": "1f2e3d4c5b6a7988c0d2e4f6a8b0c2d4",
  "timestamp": "2026-01-31T10:01:10Z",
  "tamper_proof": true
}
```

Important behavior:

- Stores blocks in memory.
- Each block includes the previous hash.
- This simulates tamper-evident logging.

Presentation point:

> The Ledger stub demonstrates the interface and data shape expected from the real ledger service, without implementing production blockchain anchoring.

---

### 9.4 Response Stub

File:

```text
services/response/app.py
```

Runs on:

```text
8004
```

Routes:

```text
GET  /health
POST /response/terminate
POST /response/isolate
POST /response/recover
POST /response/trigger
```

Purpose:

- Simulates incident response actions.

Example actions:

- Terminate suspicious process
- Isolate network
- Recover files
- Trigger automated response

Example trigger response:

```json
{
  "status": "success",
  "actions_taken": [
    "process_terminated",
    "network_isolated",
    "admin_notified"
  ],
  "timestamp": "2026-01-31T10:02:45Z"
}
```

Presentation point:

> The Response stub lets us demonstrate automated recovery flow without performing real system-level operations.

---

## 10. Dockerfiles

Each service has a Dockerfile.

General pattern:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE <port>
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "<port>"]
```

For the dashboard, the command is:

```dockerfile
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
```

Purpose:

- Each service can run independently in a container.
- Docker Compose builds and starts them together.

Presentation point:

> Containerization ensures every team member runs the same environment regardless of their local machine setup.

---

## 11. Authentication Flow

All gateway routes are protected except:

```text
GET  /health
POST /auth/token
```

Steps:

1. User gets a dev token from `/auth/token`.
2. User sends token in the `Authorization` header.
3. Gateway validates the token.
4. If valid, request continues.
5. If invalid, gateway returns `401`.

Example:

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"sub":"user_id_123","role":"admin","tier":"enterprise"}'
```

Use token:

```bash
curl http://localhost:8000/monitor/status \
  -H "Authorization: Bearer <token>"
```

Presentation point:

> JWT authentication protects the gateway while keeping the Phase 4 setup simple enough for local testing.

---

## 12. Rate Limiting Flow

After authentication, the gateway applies rate limiting.

Flow:

```text
Request arrives
      |
JWT is validated
      |
Tier is read from JWT
      |
Token bucket is checked
      |
Request is allowed or rejected
```

If the limit is exceeded, the gateway returns:

```text
HTTP 429 Too Many Requests
```

Presentation point:

> Rate limiting protects API resources and supports different usage tiers like Free, Premium, and Enterprise.

---

## 13. `/analyze` End-to-End Flow

The `/analyze` endpoint is the most important integration route.

Request:

```json
{
  "file_path": "/path/to/file.doc"
}
```

Internal flow:

```text
1. Gateway receives file path.
2. Gateway calls Monitor /features.
3. Monitor returns file features.
4. Gateway calls ML Engine /predict.
5. ML Engine returns prediction.
6. Gateway calls Ledger /ledger/log.
7. Ledger stores event.
8. Gateway returns prediction to client.
```

Response:

```json
{
  "prediction": "ransomware",
  "confidence": 0.94,
  "model_version": "1.0.0",
  "timestamp": "2026-01-31T10:01:05Z",
  "threat_level": "high",
  "features_importance": {
    "shannon_entropy": 0.35,
    "modification_rate": 0.28,
    "api_calls": 0.22
  }
}
```

Presentation point:

> `/analyze` demonstrates real service orchestration, because one gateway request triggers three backend service calls in sequence.

---

## 14. Testing

Test file:

```text
services/gateway/tests/test_gateway.py
```

The tests use pytest and FastAPI TestClient.

Tests included:

1. `/health` works without authentication.
2. Protected routes reject missing JWT.
3. Dev token can access protected routes.
4. `/predict` returns correct contract-shaped JSON.
5. `/analyze` calls Monitor, ML, and Ledger in order.
6. `/response/trigger` supports the response flow.
7. Rate limiting returns standard `429` error.

Command:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r services/gateway/requirements.txt
pytest services/gateway/tests -q
```

Verified result:

```text
7 passed
```

Presentation point:

> The gateway tests prove the integration layer works even before real teammate service internals are complete.

---

## 15. How to Run the Project

Step 1: Copy environment file.

```bash
cp .env.example .env
```

Step 2: Start all containers.

```bash
docker compose up -d --build
```

Step 3: Check running containers.

```bash
docker compose ps
```

Step 4: Open gateway health.

```text
http://localhost:8000/health
```

Step 5: Open dashboard.

```text
http://localhost:8501
```

Step 6: View logs if needed.

```bash
docker compose logs -f gateway
docker compose logs -f dashboard
```

Step 7: Stop system.

```bash
docker compose down
```

Important note:

Docker Desktop must be running before using Docker Compose.

---

## 16. Demo Script for Presentation

Use this sequence during presentation:

1. Show the architecture diagram.
2. Explain that the gateway is the central integration point.
3. Run:

```bash
docker compose up -d --build
```

4. Open:

```text
http://localhost:8000/health
```

Explain:

> This shows the gateway checking all downstream services.

5. Open:

```text
http://localhost:8501
```

Explain:

> This is the Streamlit dashboard. It refreshes every second and displays live file events, entropy, ML metrics, and ledger information.

6. Generate a token:

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"sub":"user_id_123","role":"admin","tier":"enterprise"}'
```

7. Call `/analyze`:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"/watch/demo_file.doc"}'
```

Explain:

> This single request triggers Monitor feature extraction, ML prediction, and Ledger logging.

---

## 17. What to Say in Presentation

Short explanation:

> My role was Integration and DevOps Lead. I built the API Gateway, dashboard, Docker Compose setup, OpenAPI contract, tests, and temporary stubs for teammate-owned services. The gateway centralizes authentication, rate limiting, routing, error formatting, and service orchestration. The dashboard connects only to the gateway and displays live monitoring, prediction, and ledger information.

Detailed explanation:

> Since the real Monitor, ML Engine, Ledger, and Response service logic is owned by other teammates, I created lightweight placeholder services that follow the same API contracts. This allowed me to build and test the complete integration layer early. When teammates finish their real services, they can replace the stubs as long as they keep the same endpoints and JSON formats.

Key technical points:

- FastAPI gateway on port `8000`
- Streamlit dashboard on port `8501`
- Four backend services on ports `8001` to `8004`
- JWT authentication
- Tiered rate limiting
- Standard error format
- OpenAPI 3.0 contract
- Docker Compose one-command startup
- `/analyze` orchestration across Monitor, ML, and Ledger
- pytest gateway tests

---

## 18. How Teammates Can Replace Stubs

The real services should keep the same endpoint contracts.

For example, the real ML Engine should still expose:

```text
POST /predict
GET  /model/metrics
GET  /health
```

The gateway does not need to know how the ML model works internally. It only needs the same JSON request and response format.

If a service URL changes, update:

```env
MONITOR_URL=
ML_URL=
LEDGER_URL=
RESPONSE_URL=
```

in `.env` or `docker-compose.yml`.

Presentation point:

> This design separates service implementation from service integration, which is one of the main benefits of microservices.

---

## 19. Current Verification Status

Completed checks:

```text
Gateway tests: 7 passed
OpenAPI validation: passed
Python compile check: passed
Docker Compose config parse: passed
```

Docker startup note:

The full Docker startup command was attempted, but Docker Desktop was not running at that time. The Compose file itself parsed successfully. Once Docker Desktop is running, the command should be:

```bash
docker compose up -d --build
```

---

## 20. Future Work

The following are intentionally not implemented in this phase:

- CI/CD pipeline
- Production load balancing
- Real blockchain anchoring
- Real user management system
- Production-grade secret management
- Real Monitor/ML/Ledger/Response internal logic

These are future phase tasks.

---

## 21. Final Summary

This implementation creates a complete integration-ready version of URDS for the SH role.

It includes:

- A working FastAPI API Gateway
- JWT authentication
- Tiered rate limiting
- Standard error responses
- Gateway service routing
- `/analyze` orchestration
- Streamlit dashboard
- Docker Compose orchestration
- OpenAPI documentation
- Placeholder backend services
- Gateway tests

The main value of this work is that the whole project can now be run, tested, demonstrated, and integrated before the final teammate-owned service internals are complete.
