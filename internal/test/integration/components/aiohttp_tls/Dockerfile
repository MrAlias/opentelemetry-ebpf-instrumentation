FROM python:3.14.3-slim@sha256:6a27522252aef8432841f224d9baaa6e9fce07b07584154fa0b9a96603af7456 AS base

# OBI's asyncio probes require CPython's unstripped private symbols.
FROM base AS python
ARG TARGETARCH
ADD --checksum=sha256:d4c6712210b69540ab4ed51825b99388b200e4f90ca4e53fbb5a67c2467feb48 https://github.com/astral-sh/python-build-standalone/releases/download/20260203/cpython-3.14.3%2B20260203-x86_64-unknown-linux-gnu-install_only.tar.gz /tmp/python-amd64.tar.gz
ADD --checksum=sha256:f6528fc435468bd0212003bc3d4db0fabb995ceec7dc0fba3450744834be569a https://github.com/astral-sh/python-build-standalone/releases/download/20260203/cpython-3.14.3%2B20260203-aarch64-unknown-linux-gnu-install_only.tar.gz /tmp/python-arm64.tar.gz
RUN mkdir -p /opt/python && \
    tar -xzf "/tmp/python-${TARGETARCH}.tar.gz" --strip-components=1 -C /opt/python

FROM base AS runtime
COPY --from=python /opt/python /opt/python
ENV PATH="/opt/python/bin:$PATH"
WORKDIR /app
COPY internal/test/integration/components/aiohttp_tls/requirements.txt .
RUN python -m pip install --require-hashes -r requirements.txt
COPY internal/test/integration/components/aiohttp_tls/*.py ./
COPY internal/test/integration/components/pythonserver/server.crt ./
COPY internal/test/integration/components/pythonserver/server.key ./
ENTRYPOINT ["python"]
