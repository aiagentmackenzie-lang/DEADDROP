"""Pydantic models for the DEADDROP API — every body is validated (SB-4 fix)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
EvidenceType = Literal["disk", "memory"]
ReportFormat = Literal["html", "pdf"]
TimelineFormat = Literal["csv", "json", "body"]


class CaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    analyst: str = Field("", max_length=100)
    notes: str = Field("", max_length=2000)


class CaseUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    analyst: str | None = Field(None, max_length=100)
    status: Literal["open", "closed", "archived"] | None = None
    notes: str | None = Field(None, max_length=2000)


class DiskIngest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    image_path: str = Field(..., min_length=1, max_length=4096)


class MemoryIngest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    dump_path: str = Field(..., min_length=1, max_length=4096)


class AnalyzeRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    evidence_id: str | None = Field(None, max_length=64)


class MemoryAnalyzeRequest(AnalyzeRequest):
    plugin: str = Field("windows.pslist", max_length=100)


class EventAnalyzeRequest(AnalyzeRequest):
    source: str | None = Field(None, max_length=100)


class HuntYaraRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    yara_rules: str | None = Field(None, max_length=4096)
    pack: Literal["persistence", "lateral_movement", "exfiltration"] | None = None


class HuntIOCRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    ioc_path: str = Field(..., min_length=1, max_length=4096)


class TriageRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)


class ReportRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    format: ReportFormat = "html"
    output_path: str | None = Field(None, max_length=4096)


class TimelineExportRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    format: TimelineFormat = "csv"
    output_path: str | None = Field(None, max_length=4096)


class TimelineFilterRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    from_ts: str | None = None
    to_ts: str | None = None
    source: str | None = Field(None, max_length=100)


class PluginRunRequest(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=100)
