FROM python:3.13-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir --break-system-packages sentinel-code-review

ENTRYPOINT ["sentinel"]
