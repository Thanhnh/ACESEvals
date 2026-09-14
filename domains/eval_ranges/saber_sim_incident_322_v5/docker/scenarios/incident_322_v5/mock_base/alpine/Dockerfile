FROM python:3.11-alpine
COPY wheels/ /tmp/wheels/
RUN PKGS='flask pyyaml'; \
    pip install --no-cache-dir --retries 5 --timeout 30 $PKGS \
    || pip install --no-cache-dir --no-index --find-links=/tmp/wheels $PKGS; \
    rm -rf /tmp/wheels
