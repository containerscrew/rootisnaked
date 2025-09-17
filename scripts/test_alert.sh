#! /usr/bin/env bash

START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo $START

cat <<EOF | curl -v -X POST "http://localhost:9093/api/v2/alerts" \
  -H "Content-Type: application/json" -d @-
[
  {
    "labels": {
      "alertname": "Privilege escalation attempt",
      "severity": "critical",
      "instance": "darlene"
    },
    "annotations": {
        "title": "Someone is trying to gain root access",
        "description": "This is a test alert for critical severity"
    },
    "startsAt": "${START}"
  }
]
EOF
