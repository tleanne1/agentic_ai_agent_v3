🧠 agentic_ai_agent_v3
Autonomous SOC Threat Hunting Engine
Agentic SOC Engine – Autonomous Threat Hunting Platform

Author: Tracey Buentello
Role: SOC Engineer / Threat Hunter
Platform Type: Cognitive SOC Analysis Engine
Status: Portfolio-grade SOC simulation platform
Supports: Live Azure Telemetry & Demo SOC Environments

Platforms and Languages Leveraged
Platforms

Microsoft Defender for Endpoint (MDE)

Azure Log Analytics Workspace

Windows & Linux corporate endpoints

OpenAI Cognitive Analysis Models

Languages / Tools

Python

Kusto Query Language (KQL)

Azure Monitor SDK

OpenAI API

PowerShell (optional containment actions)

Purpose

This engine simulates how a real Security Operations Center triages, pivots, escalates, and prioritizes security telemetry — from analyst intent to kill-chain assessment and executive reporting.

Unlike rule-based tools, this engine accepts natural language SOC prompts and performs:

Automated query construction

Telemetry execution

Baseline anomaly detection

Pivot investigation

Kill-chain modeling

Escalation scoring

LLM-driven cognitive hunting

Executive SOC summary generation

SOC Workflow Simulated
Phase	What the Engine Does
Detection	Translates analyst intent into KQL telemetry hunts
Triage	Builds safe query contexts and executes telemetry
Baseline	Detects rare or unusual behavior
Investigation	Auto-pivots related telemetry
Kill Chain	Scores compromise progression
Escalation	Calculates severity & response readiness
Cognitive Hunt	LLM interprets telemetry for hidden threats
Reporting	Generates executive SOC summaries
Containment	Advisory-only isolation (human-approved)
Example SOC Hunt Flow

Prompt Entered

Hunt suspicious logons on all devices in the last 24 hours


Engine Automatically Performs

Selects DeviceLogonEvents telemetry

Builds time-bound KQL queries

Executes baseline anomaly detection

Generates pivot evidence

Runs kill-chain progression analysis

Produces escalation scoring

Runs LLM cognitive hunt

Outputs executive SOC summary

Executive SOC Output (Example)
Section	Description
Targets	Affected endpoints
Anomalies	Rare or abnormal behavior
Kill Chain	Observed compromise stages
Escalation	SOC action readiness
Findings	Cognitive threat results
Isolation	Human-approved containment status
SOC Guardrails

❌ No automated blocking

❌ No forced containment

❌ No destructive actions

✔ Advisory-only decision engine

✔ Human approval required

Repository Modules
Module	Function
EXECUTOR.py	Telemetry execution
BASELINES.py	Behavioral anomaly baselines
PLANNER.py	Pivot investigation logic
KILLCHAIN.py	Compromise modeling
PROMPT_MANAGEMENT.py	LLM prompt shaping
GUARDRAILS.py	Safety and injection defense
_main.py	CLI SOC console
api_server.py	REST interface for UI
