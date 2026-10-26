FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_EC2_METADATA_V1_DISABLED=true \
    AWS_METADATA_SERVICE_TIMEOUT=1 \
    AWS_METADATA_SERVICE_NUM_ATTEMPTS=2

WORKDIR /app
COPY services/aws-credential-broker/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/aws-credential-broker/app.py ./app.py
USER 10001:10001
EXPOSE 18443
CMD ["python", "/app/app.py"]
