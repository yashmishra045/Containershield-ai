# ContainerShield AI

Docker image security scanner — vulnerability detection (Trivy + Grype),
secret detection (Gitleaks), SBOM generation (Syft), risk scoring,
a React dashboard, and PDF reports. This is the Semester-7 scope from
the project synopsis.

## Prerequisites

- Docker + Docker Compose
- Node.js 18+ (only if you want to run the frontend outside Docker)
- The backend Docker image installs Trivy, Grype, Syft, and Gitleaks
  automatically — you don't need to install them on your host.

## Quick start (recommended — everything in Docker)

```bash
cd containershield-ai
docker compose up --build
```

This starts:
- **Postgres** on `localhost:5432`
- **Backend (FastAPI)** on `http://localhost:8000`

The backend container is given access to your host's Docker socket
(`/var/run/docker.sock`) so it can pull and inspect the images you ask
it to scan.

Then run the frontend separately (Vite dev server isn't containerized
here, keeps hot-reload fast):

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`, type an image name like `nginx:latest`,
and hit **Scan Image**.

## Running the backend without Docker (local dev)

1. Install Postgres locally, or just run `docker compose up db`.
2. Install the scanner tools on your machine:
   - Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
   - Grype: https://github.com/anchore/grype#installation
   - Syft: https://github.com/anchore/syft#installation
   - Gitleaks: https://github.com/gitleaks/gitleaks#getting-started
3. ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp .env.example .env          # edit DATABASE_URL if needed
   uvicorn app.main:app --reload
   ```

## API endpoints

| Method | Path                    | Description                          |
|--------|--------------------------|--------------------------------------|
| POST   | `/scan`                  | Start a scan: `{"image_name": "nginx:latest"}` |
| GET    | `/scan/{id}`              | Get scan status + full results       |
| GET    | `/scans`                  | List recent scans                    |
| GET    | `/scan/{id}/report`       | Download PDF report                  |
| GET    | `/health`                 | Health check                         |

## How a scan works

1. `POST /scan` creates a DB row (`status: pending`) and returns immediately.
2. A background task runs Trivy + Grype (vulnerabilities), Gitleaks
   (secrets, via `docker export` of the image filesystem), and Syft
   (SBOM).
3. Results are normalized into a common shape, deduplicated across
   Trivy/Grype, and a weighted risk score (0–100) is calculated.
4. Everything is written to Postgres; the frontend polls `/scan/{id}`
   every 3 seconds until `status` becomes `done` or `failed`.

## Project structure

```
containershield-ai/
├── backend/
│   ├── app/
│   │   ├── main.py        # FastAPI routes
│   │   ├── models.py      # SQLAlchemy models (Postgres)
│   │   ├── schemas.py     # Pydantic request/response schemas
│   │   ├── scanner.py     # Trivy/Grype/Gitleaks/Syft wrappers + normalization
│   │   ├── report.py      # PDF report generation (ReportLab)
│   │   └── database.py    # DB session setup
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx        # Scan form + dashboard + charts
│       └── main.jsx
├── docker-compose.yml
└── README.md
```

## Known limitations (fine for Semester 7 — flag these as "future work")

- No auth on the API — anyone who can reach it can trigger scans.
- Gitleaks step needs Docker socket access, which is a real security
  consideration for a container-security tool itself — worth a line
  in your report's limitations section.
- Risk score formula is a simple weighted count, not CVSS-based.
- Semester 8 items (AI remediation, CIS benchmark, CI/CD integration,
  scan history/trends) are intentionally not built here.

## Next steps for you

1. `docker compose up --build` and confirm Postgres + backend come up.
2. Run the frontend, scan `nginx:latest` and `alpine:3.10` (old, will
   have lots of CVEs) to see the dashboard populate.
3. Download a PDF report to check formatting.
4. Write up Semester-7 documentation using this as the working system.
