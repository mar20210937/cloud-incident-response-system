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

```bash
uvicorn app.main:app --reload
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
-e SNS_TOPIC_ARN="arn:aws:sns:us-east-1:870676149540:CloudIncidentAlerts" \
cloud-incident-backend

http://EC2_PUBLIC_IP:8000/docs
http://EC2_PUBLIC_IP:8000/storage/status