FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN uv pip install --system -r requirements.txt

# Copy application code
COPY opnsense_mcp_server.py .

# Expose port (for future HTTP transport support)
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["python", "opnsense_mcp_server.py"] 