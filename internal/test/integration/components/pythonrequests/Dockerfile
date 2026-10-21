ARG PYTHON_IMAGE=python:3.14@sha256:7aea6827c8787754f99339ffed8cfc41fb09421f9c7d0e77a198b08422a3455e
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY internal/test/integration/components/pythonrequests/requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY internal/test/integration/components/pythonrequests/*.py .
COPY internal/test/integration/components/pythonserver/server.crt .
COPY internal/test/integration/components/pythonserver/server.key .
CMD ["python", "source.py"]
