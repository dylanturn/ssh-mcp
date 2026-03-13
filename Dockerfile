FROM python:3.11-slim

WORKDIR /app

# Install openssh-client so the system known_hosts file is available
# when SSH_MCP_HOST_KEY_POLICY=reject (the default)
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy only the files needed to install the package first so that
# Docker can cache the dependency layer independently of source changes
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Default to the HTTP transport so the image works out-of-the-box when run
# with `docker run` or docker compose.  STDIO is the library default but is
# not useful inside a container.
ENV SSH_MCP_TRANSPORT=streamable-http \
    SSH_MCP_HOST=0.0.0.0 \
    SSH_MCP_PORT=8000

EXPOSE 8000

ENTRYPOINT ["ssh-mcp"]
