FROM google/cloud-sdk:slim

RUN apt-get update && apt-get install -y python3-pip git curl && \
    rm -rf /var/lib/apt/lists/*

# crane — needed to pull the live grocerguard image and sync deployed source into CODEBASE_DIR
# before each run, so red team builds on top of blue team's latest patches.
RUN curl -L https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz | tar -xz -C /usr/local/bin crane

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "0", "main:app"]
