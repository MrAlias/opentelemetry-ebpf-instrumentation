FROM python:3.12.13-bookworm@sha256:3cd9086bdb30f7c9bc08a3fa621d9842e0d3f6f9291aeb4677e0547817c10b12

WORKDIR /app
COPY internal/test/integration/components/pythonhttpx/requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY internal/test/integration/components/pythonserver/server.crt internal/test/integration/components/pythonserver/server.key ./
COPY internal/test/integration/components/pythonhttpx/*.py ./
