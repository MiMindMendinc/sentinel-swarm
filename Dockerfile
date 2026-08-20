FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system sentinel && adduser --system --ingroup sentinel sentinel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app

USER sentinel
EXPOSE 7777

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7777"]
