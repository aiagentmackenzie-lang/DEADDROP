FROM python:3.12-slim

WORKDIR /app

# System dependencies for forensics tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libewf-dev \
    libtsk-dev \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Application code
COPY src/ src/
COPY rules/ rules/

# Install in development mode
RUN pip install -e .

ENTRYPOINT ["deaddrop"]