FROM python:3.14@sha256:61346539f7b26521a230e72c11da5ebd872924745074b19736e7d65ba748c366

COPY internal/test/integration/components/python_grpc_tls/requirements.txt /requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt
RUN openssl req -x509 -newkey rsa:2048 -nodes -keyout /key.pem -out /cert.pem \
    -days 3650 -subj /CN=proxy -addext subjectAltName=DNS:proxy
COPY internal/test/integration/components/python_grpc_tls/*.py /app/
WORKDIR /app
CMD ["python", "source.py"]
