# Cloud Incident Response System

This project is a Dockerized cloud incident response backend built using FastAPI.

It receives security and system events, detects suspicious behavior using rule-based logic, classifies incidents by severity, and records response actions.

## Features

- Event collection API
- Brute-force login detection
- Invalid token / unauthorized access detection
- High request rate detection
- Service failure detection
- System overload detection
- Severity classification
- Controlled response actions
- Dockerized backend

## Run Locally

Run this command:

```bash
uvicorn app.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## Run with Docker

Build the image:

```bash
docker build -t cloud-incident-backend .
```

Run the container:

```bash
docker run --rm -p 8000:8000 cloud-incident-backend
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## AWS Deployment

The backend was deployed on an AWS EC2 instance using Docker.

### AWS Services Used

- EC2: Hosts the Dockerized FastAPI backend.
- DynamoDB: Stores detected incident records.
- CloudWatch Logs: Stores backend logs and incident activity.
- SNS: Sends email alerts for High and Critical incidents.
- IAM Role: Allows EC2 to access DynamoDB, CloudWatch, and SNS without hardcoded credentials.

### Run on EC2

```bash
docker run -d --name cloud-incident-backend -p 8000:8000 \
-e DYNAMODB_ENABLED=true \
-e AWS_REGION=us-east-1 \
-e AWS_DEFAULT_REGION=us-east-1 \
-e DYNAMODB_TABLE=CloudIncidents \
-e CLOUDWATCH_ENABLED=true \
-e CLOUDWATCH_LOG_GROUP=/cloud-incident-response/backend \
-e SNS_ENABLED=true \
-e SNS_TOPIC_ARN="arn:aws:sns:us-east-1:<account-id>:CloudIncidentAlerts"
cloud-incident-backend
```

### Test URLs

```text
http://EC2_PUBLIC_IP:8000/docs
http://EC2_PUBLIC_IP:8000/storage/status
```

### Main Detection Rules

- Failed login attempts: 5 failed logins within 60 seconds → High severity.
- Invalid token attempts: 3 invalid token attempts → Critical severity.
- High request rate: 100 requests per minute → Medium severity.
- Service failure: health check failure → Critical severity.
- System overload: CPU above 85% for 120 seconds → High severity.