FROM google/cloud-sdk:slim

RUN apt-get update && apt-get install -y python3-pip git curl && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fL --retry 3 --retry-delay 5 -o /tmp/crane.tgz \
      https://github.com/google/go-containerregistry/releases/download/v0.21.5/go-containerregistry_Linux_x86_64.tar.gz && \
    tar -xz -C /usr/local/bin -f /tmp/crane.tgz crane && \
    rm /tmp/crane.tgz

WORKDIR /app
COPY agent-src/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY agent-src/ .

# Bundle the grocerguard-app source so the agent can read, patch, and redeploy it
COPY grocerguard-app-src/ /workspace/grocerguard-arena/grocerguard-app/

ENV PYTHONUNBUFFERED=1
ENV CODEBASE_DIR=/workspace/grocerguard-arena/grocerguard-app
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "0", "main:app"]
