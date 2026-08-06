# 3.13 to match the environment the models were trained in. xgboost 3.4 also
# requires >=3.12, so 3.11-slim cannot install the pinned versions at all.
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
# This image pulls ~65MB of scientific wheels. Docker Desktop's VM network drops
# large transfers often enough that the default 5 retries / 15s timeout leaves
# the build wedged mid-download.
RUN pip install --no-cache-dir --retries 10 --timeout 120 -r requirements.txt
COPY *.py ./

EXPOSE 8002
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8002"]
