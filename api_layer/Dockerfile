FROM python:3.11-alpine AS base

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONENV=production
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/app/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install system dependencies
RUN apk add --no-cache postgresql-dev gcc musl-dev curl

# Create virtual environment
RUN python -m venv $VIRTUAL_ENV

# Install Python dependencies first (for better caching)
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code with correct ownership (avoids a separate chown layer for source files)
COPY --chown=appuser:appgroup auth ./auth
COPY --chown=appuser:appgroup config ./config
COPY --chown=appuser:appgroup middleware ./middleware
COPY --chown=appuser:appgroup routes ./routes
COPY --chown=appuser:appgroup utils ./utils
COPY --chown=appuser:appgroup main.py ./

# Chown venv and non-source files (requirements.txt) to match original ownership
RUN chown -R appuser:appgroup /app/venv /app/requirements.txt

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5006

# Run FastAPI with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5006", "--workers", "1"] 