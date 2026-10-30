FROM python:3.12-slim AS gen
COPY generate_logs.py /gen/generate_logs.py
RUN python3 /gen/generate_logs.py --out /out

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=gen /out/ /var/log/
WORKDIR /app