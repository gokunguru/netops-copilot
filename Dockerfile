# syntax=docker/dockerfile:1

# ---- build: produce a wheel from the sources ----
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

# ---- runtime: wheel + lab inventory, non-root ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETOPS_HOST=0.0.0.0 \
    NETOPS_PORT=8000 \
    NETOPS_INVENTORY=/app/lab/inventory.yml \
    NETOPS_MOCK=1
# Offline model by default: run with -e NETOPS_MOCK=0 -e META_API_KEY=... for Muse Spark.

RUN useradd --create-home --uid 10001 netops
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY lab ./lab

USER netops
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["netops-copilot-web"]
