# DEADDROP Docker — single-service image: FastAPI API + built dashboard.
#
# Stage 1 builds the React dashboard (Vite → static dist).
# Stage 2 installs the Python app (with disk/memory/pdf extras) and serves
# both the API and the dashboard via uvicorn. The previous compose stack ran
# the engine and a Node server in separate containers with a subprocess bridge
# that couldn't reach the `deaddrop` binary across containers (SB-3). One image,
# in-process engine — no bridge.

# ── Stage 1: dashboard build ──────────────────────────────────
FROM node:20-slim AS dashboard-builder
WORKDIR /dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build  # → /dashboard/dist

# ── Stage 2: Python app + dashboard static ─────────────────────
FROM python:3.12-slim AS runtime

# System deps: forensics libs (libewf/pytsk), YARA, PDF rendering (pango/gdk-pixbuf)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libewf-dev libtsk-dev yara \
    libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src/ src/
COPY rules/ rules/
COPY README.md ./

# Install the app with the forensic extras (disk/memory/pdf) + API deps.
# WeasyPrint system libs are satisfied above; pytsk3 builds against libtsk-dev.
RUN pip install --no-cache-dir ".[disk,memory,pdf]"

# Copy the built dashboard so the FastAPI lifespan serves it at /
COPY --from=dashboard-builder /dashboard/dist /app/dashboard/dist

ENV PYTHONUNBUFFERED=1 \
    DEADDROP_HOST=0.0.0.0 \
    DEADDROP_PORT=8080
# NOTE: set DEADDROP_API_TOKEN in the compose env or at runtime. The app refuses
# to serve without auth only if the token is set; binding 0.0.0.0 in the image
# is required for container networking — always pair with a token in production.

EXPOSE 8080
VOLUME ["/root/.deaddrop"]

ENTRYPOINT ["deaddrop"]
CMD ["dashboard", "--host", "0.0.0.0", "--port", "8080"]