from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import os
import uuid
import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


app = FastAPI(title="Cloud Incident Response System")

# Local in-memory storage.
# This keeps the app working locally even when DynamoDB is disabled.
events = []
incidents = []

# DynamoDB configuration.
# Locally this is disabled by default.
# On EC2, we will enable it using environment variables.
DYNAMODB_ENABLED = os.getenv("DYNAMODB_ENABLED", "false").lower() == "true"
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE", "CloudIncidents")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

dynamodb_table = None

if DYNAMODB_ENABLED:
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    dynamodb_table = dynamodb.Table(DYNAMODB_TABLE_NAME)


# Trackers for time-window detection
failed_login_tracker: Dict[str, List[datetime]] = defaultdict(list)
invalid_token_tracker: Dict[str, List[datetime]] = defaultdict(list)
request_rate_tracker: Dict[str, List[datetime]] = defaultdict(list)

# Safety control: trusted IPs should not be blocked
ALLOWLISTED_IPS = {
    "127.0.0.1",
    "10.0.0.5"
}


class Event(BaseModel):
    event_type: str
    source_ip: str
    username: Optional[str] = None
    status: Optional[str] = None
    timestamp: Optional[str] = None

    request_count: Optional[int] = 1
    cpu_percent: Optional[float] = None
    duration_seconds: Optional[int] = None
    service_name: Optional[str] = None


@app.get("/health")
def health_check():
    return {
        "status": "running",
        "service": "Cloud Incident Response System"
    }


@app.get("/storage/status")
def storage_status():
    return {
        "dynamodb_enabled": DYNAMODB_ENABLED,
        "table_name": DYNAMODB_TABLE_NAME,
        "region": AWS_REGION,
        "local_incident_count": len(incidents)
    }


@app.post("/events")
def receive_event(event: Event):
    event_time = parse_event_time(event.timestamp)

    event_data = event.dict()
    event_data["processed_at"] = event_time.isoformat()
    events.append(event_data)

    detected_incident = None

    if event.source_ip in ALLOWLISTED_IPS:
        return {
            "message": "Event received but source IP is allowlisted",
            "incident_detected": False,
            "incident": None
        }

    if event.event_type == "failed_login":
        detected_incident = detect_brute_force(event.source_ip, event_time)

    elif event.event_type == "invalid_token":
        detected_incident = detect_invalid_token_attempts(event.source_ip, event_time)

    elif event.event_type == "api_request":
        detected_incident = detect_high_request_rate(
            source_ip=event.source_ip,
            event_time=event_time,
            request_count=event.request_count or 1
        )

    elif event.event_type == "service_failure":
        detected_incident = detect_service_failure(
            source_ip=event.source_ip,
            service_name=event.service_name,
            event_time=event_time
        )

    elif event.event_type == "system_metric":
        detected_incident = detect_system_overload(
            source_ip=event.source_ip,
            cpu_percent=event.cpu_percent,
            duration_seconds=event.duration_seconds,
            event_time=event_time
        )

    return {
        "message": "Event received",
        "incident_detected": detected_incident is not None,
        "incident": detected_incident
    }


@app.get("/events")
def get_events():
    return events


@app.get("/incidents")
def get_incidents():
    if DYNAMODB_ENABLED:
        try:
            response = dynamodb_table.scan()
            items = response.get("Items", [])

            formatted_items = []
            for item in items:
                if "details" in item and isinstance(item["details"], str):
                    try:
                        item["details"] = json.loads(item["details"])
                    except json.JSONDecodeError:
                        pass

                formatted_items.append(item)

            return formatted_items

        except (BotoCoreError, ClientError, NoCredentialsError) as error:
            return {
                "message": "Failed to read from DynamoDB. Returning local incidents instead.",
                "error": str(error),
                "local_incidents": incidents
            }

    return incidents


def parse_event_time(timestamp: Optional[str]):
    if timestamp:
        try:
            return datetime.fromisoformat(timestamp.replace("Z", ""))
        except ValueError:
            return datetime.utcnow()

    return datetime.utcnow()


def create_incident(
    incident_type: str,
    source_ip: str,
    severity: str,
    response_action: str,
    event_time: datetime,
    details: Optional[dict] = None
):
    incident = {
        "incident_id": str(uuid.uuid4()),
        "incident_type": incident_type,
        "source_ip": source_ip,
        "severity": severity,
        "response_action": response_action,
        "status": "detected",
        "created_at": event_time.isoformat(),
        "details": details or {}
    }

    incidents.append(incident)

    if DYNAMODB_ENABLED:
        save_incident_to_dynamodb(incident)

    return incident


def save_incident_to_dynamodb(incident: dict):
    try:
        dynamodb_item = {
            "incident_id": incident["incident_id"],
            "incident_type": incident["incident_type"],
            "source_ip": incident["source_ip"],
            "severity": incident["severity"],
            "response_action": incident["response_action"],
            "status": incident["status"],
            "created_at": incident["created_at"],
            "details": json.dumps(incident["details"])
        }

        dynamodb_table.put_item(Item=dynamodb_item)

    except (BotoCoreError, ClientError, NoCredentialsError) as error:
        incident["dynamodb_save_error"] = str(error)


def detect_brute_force(source_ip: str, event_time: datetime):
    time_window = timedelta(seconds=60)

    failed_login_tracker[source_ip].append(event_time)

    recent_attempts = [
        attempt_time
        for attempt_time in failed_login_tracker[source_ip]
        if event_time - attempt_time <= time_window
    ]

    failed_login_tracker[source_ip] = recent_attempts

    if len(recent_attempts) >= 5:
        failed_login_tracker[source_ip] = []

        return create_incident(
            incident_type="brute_force_attempt",
            source_ip=source_ip,
            severity="High",
            response_action="IP flagged temporarily",
            event_time=event_time,
            details={
                "failed_login_count": len(recent_attempts),
                "time_window_seconds": 60
            }
        )

    return None


def detect_invalid_token_attempts(source_ip: str, event_time: datetime):
    time_window = timedelta(seconds=60)

    invalid_token_tracker[source_ip].append(event_time)

    recent_attempts = [
        attempt_time
        for attempt_time in invalid_token_tracker[source_ip]
        if event_time - attempt_time <= time_window
    ]

    invalid_token_tracker[source_ip] = recent_attempts

    if len(recent_attempts) >= 3:
        invalid_token_tracker[source_ip] = []

        return create_incident(
            incident_type="unauthorized_access_attempt",
            source_ip=source_ip,
            severity="Critical",
            response_action="Admin approval required before blocking",
            event_time=event_time,
            details={
                "invalid_token_count": len(recent_attempts),
                "time_window_seconds": 60
            }
        )

    return None


def detect_high_request_rate(source_ip: str, event_time: datetime, request_count: int):
    time_window = timedelta(seconds=60)

    for _ in range(request_count):
        request_rate_tracker[source_ip].append(event_time)

    recent_requests = [
        request_time
        for request_time in request_rate_tracker[source_ip]
        if event_time - request_time <= time_window
    ]

    request_rate_tracker[source_ip] = recent_requests

    if len(recent_requests) >= 100:
        request_rate_tracker[source_ip] = []

        return create_incident(
            incident_type="abnormal_request_rate",
            source_ip=source_ip,
            severity="Medium",
            response_action="Traffic source flagged for monitoring",
            event_time=event_time,
            details={
                "request_count": len(recent_requests),
                "time_window_seconds": 60
            }
        )

    return None


def detect_service_failure(source_ip: str, service_name: Optional[str], event_time: datetime):
    return create_incident(
        incident_type="service_failure",
        source_ip=source_ip,
        severity="Critical",
        response_action="Service restart recommended and administrator alerted",
        event_time=event_time,
        details={
            "service_name": service_name or "unknown_service"
        }
    )


def detect_system_overload(
    source_ip: str,
    cpu_percent: Optional[float],
    duration_seconds: Optional[int],
    event_time: datetime
):
    if cpu_percent is None or duration_seconds is None:
        return None

    if cpu_percent > 85 and duration_seconds >= 120:
        return create_incident(
            incident_type="system_overload",
            source_ip=source_ip,
            severity="High",
            response_action="System marked as overloaded and administrator alerted",
            event_time=event_time,
            details={
                "cpu_percent": cpu_percent,
                "duration_seconds": duration_seconds
            }
        )

    return None