FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

COPY pyproject.toml ./
COPY app/ ./app/
RUN pip install --upgrade pip && pip install -e .

# SQLite default lives here; bind-mount a volume to /data in compose for persistence.
RUN mkdir -p /data

EXPOSE 8800
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8800"]
