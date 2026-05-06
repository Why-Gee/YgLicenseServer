FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

COPY pyproject.toml ./
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh
RUN pip install --upgrade pip && pip install -e .

# SQLite default lives here; bind-mount a volume to /data in compose for persistence.
RUN mkdir -p /data

EXPOSE 8800
ENTRYPOINT ["/srv/docker-entrypoint.sh"]
