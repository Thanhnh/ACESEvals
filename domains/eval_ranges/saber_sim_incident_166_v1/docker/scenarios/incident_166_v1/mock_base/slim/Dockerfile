FROM python:3.11-slim
COPY wheels/ /tmp/wheels/
RUN PKGS='azure-storage-blob faker flask pyjwt pyopenssl pyyaml requests urllib3'; \
    pip install --no-cache-dir --retries 5 --timeout 30 $PKGS \
    || pip install --no-cache-dir --no-index --find-links=/tmp/wheels $PKGS; \
    rm -rf /tmp/wheels
