# Backend Dockerfile for Vendiant FastAPI Application
# Pin to specific digest for security and reproducibility
#
# Debian 12 "bookworm". Moved off bullseye: Debian 11 LTS ended, so the
# bullseye-security Release file expired and is no longer refreshed. apt
# rejects expired Release files, which broke every build with:
#   E: Release file for .../bullseye-security/InRelease is expired
# That repo will never be updated again, so this is permanent, not transient.
# Do NOT work around it with Acquire::Check-Valid-Until=false -- that would
# keep building a security product on a distro receiving no security patches.
FROM python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84

# Metadata labels
LABEL maintainer="vendiant-team"
LABEL version="2.0"
LABEL description="Vendiant Security Scanning Backend - FastAPI"
LABEL org.opencontainers.image.source="https://github.com/your-org/vendiant"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"
ENV VENDIANT_APP_ROOT="/app"

# Set work directory
WORKDIR /app

# Install system dependencies required by the application.
# bsdextrautils (not bsdmainutils) provides hexdump, which testssl.sh uses in
# ~60 places to parse TLS responses. On bullseye it arrived transitively via
# bsdmainutils; on bookworm bsdmainutils is a transitional oldlibs package due
# for removal, so depend on the package that actually ships the binary.
RUN apt-get update && apt-get install -y \
    dnsutils \
    whois \
    curl \
    wget \
    openssl \
    git \
    build-essential \
    libpq-dev \
    util-linux \
    coreutils \
    bsdextrautils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Update PATH to use virtual environment
ENV PATH="/app/venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/venv"

# Copy the entire Vendiant directory structure (needed for imports)
COPY . /app/

# Fetch testssl.sh (GPLv2, https://github.com/testssl/testssl.sh) at a pinned
# commit instead of vendoring it. TESTSSL_COMMIT is the commit the v3.2.5 tag
# points to; the checkout fails the build if upstream ever rewrites it.
# Upstream's bundled openssl binaries (bin/openssl.*) are deleted so testssl.sh
# uses the Debian-packaged openssl installed above (known provenance, patched
# by apt). Upstream LICENSE stays in the directory alongside the code.
ARG TESTSSL_REPO=https://github.com/testssl/testssl.sh.git
ARG TESTSSL_COMMIT=4f17be931a9d60f3f987975aea8221f1a8eaf7aa
RUN git clone --quiet --filter=blob:none --no-checkout "$TESTSSL_REPO" /app/Encryption/LOCAL/testssl.sh && \
    git -C /app/Encryption/LOCAL/testssl.sh checkout --quiet --detach "$TESTSSL_COMMIT" && \
    test "$(git -C /app/Encryption/LOCAL/testssl.sh rev-parse HEAD)" = "$TESTSSL_COMMIT" && \
    rm -rf /app/Encryption/LOCAL/testssl.sh/.git /app/Encryption/LOCAL/testssl.sh/bin/openssl.* && \
    /app/Encryption/LOCAL/testssl.sh/testssl.sh --version >/dev/null

# Set working directory to Dashboard for Flask app
WORKDIR /app/Dashboard

# Create user, directories, fix ownership, and chmod testssl in one layer
RUN groupadd --system --gid 1001 vendiant && \
    useradd --system --uid 1001 --gid vendiant --home /app --shell /bin/bash vendiant && \
    mkdir -p /app/Results/{Domain\ Reputation,Header\ Vul,Network,DNS,Encryption,All\ Domains,Alive\ Domains} \
             /app/custom_integrations/logs && \
    chown -R vendiant:vendiant /app && \
    if [ -f "/app/Encryption/LOCAL/testssl.sh/testssl.sh" ]; then \
        chmod +x /app/Encryption/LOCAL/testssl.sh/testssl.sh; \
    else \
        echo "Warning: testssl.sh script not found"; \
    fi

# Switch to non-root user
USER vendiant

# Expose port
EXPOSE 5005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5005/health || exit 1

# Run the FastAPI application with uvicorn
CMD ["python", "app_new.py"] 