FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render injects $PORT; we honor it in the start command
CMD gunicorn -w 3 -t 120 -b 0.0.0.0:${PORT:-5000} app:app
