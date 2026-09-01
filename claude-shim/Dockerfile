FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Official, portable CLI — not the VSCode-extension-bundled native binary
# (version/environment-specific, not something to depend on in a container).
RUN npm install -g @anthropic-ai/claude-code

RUN pip3 install --no-cache-dir --break-system-packages fastapi uvicorn httpx

# Deliberately empty and never bind-mounted to anything — `claude -p` is
# invoked with this as cwd. Running it against a directory with real
# project files (CLAUDE.md, git history, ...) makes Claude Code auto-discover
# and load that context into the system prompt on every single call, which
# in testing inflated per-call cost roughly 4-5x (fresh ~26k-token cache
# creation instead of a stable ~25k-token cache read) and defeated prompt
# caching entirely, since that discovered context differs by cwd/repo state.
RUN mkdir -p /empty-workdir

WORKDIR /app
COPY app ./app

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "11434"]
