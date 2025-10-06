# Multi-stage build for smaller final image
FROM python:3.10-slim AS builder

WORKDIR /app

# Install uv for faster dependency management
RUN pip install --no-cache-dir uv

# Copy requirements
COPY requirements.txt .
COPY pyproject.toml .

# Install dependencies to /app/.venv
RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install -r requirements.txt

# Final stage
FROM python:3.10-slim

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash opnsense && \
    mkdir -p /home/opnsense/.opnsense-mcp && \
    chown -R opnsense:opnsense /home/opnsense

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY --chown=opnsense:opnsense src/ /app/src/
COPY --chown=opnsense:opnsense opnsense-mcp-server.py /app/

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check (for future HTTP transport)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Switch to non-root user
USER opnsense

# Expose port for future HTTP transport support
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["python", "-m", "src.opnsense_mcp.main"]
