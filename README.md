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