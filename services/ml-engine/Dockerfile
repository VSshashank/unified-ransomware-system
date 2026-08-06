# 3.13 to match the environment the models were trained in. xgboost 3.4 also
# requires >=3.12, so 3.11-slim cannot install the pinned versions at all.
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./

EXPOSE 8002
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8002"]
