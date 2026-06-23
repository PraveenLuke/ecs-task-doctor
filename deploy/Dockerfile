FROM python:3.12-slim

RUN groupadd -r ecsdoctor && useradd -r -g ecsdoctor ecsdoctor

WORKDIR /app

COPY pyproject.toml .
COPY ecs_doctor/ ecs_doctor/

RUN pip install --no-cache-dir ".[web]"

USER ecsdoctor

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["ecs-doctor", "serve", "--host", "0.0.0.0", "--port", "8080"]
