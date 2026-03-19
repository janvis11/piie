from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContextChunk(BaseModel):
    """
    A retrieved context unit used by the GenAI system to answer a query.
    """

    doc_id: str
    chunk_id: str
    text: str
    score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """
    A tool invocation made by the GenAI system during execution.
    """

    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    output: Optional[Any] = None


class TraceStep(BaseModel):
    """
    A single execution step in an agent or workflow trace.
    """

    node: str
    input: Dict[str, Any] = Field(default_factory=dict)
    output: Dict[str, Any] = Field(default_factory=dict)


class AppOutput(BaseModel):
    """
    Canonical output returned by any GenAI system under test.
    This is the standardized contract the evaluators will consume.
    """

    query: str
    final_answer: str
    retrieved_context: List[ContextChunk] = Field(default_factory=list)
    citations: List[str] = Field(default_factory=list)
    tool_calls: List[ToolCall] = Field(default_factory=list)
    trace: List[TraceStep] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)


class MetricResult(BaseModel):
    """
    A single evaluator result for one metric.
    """

    name: str
    score: float
    passed: bool
    reason: str


class CaseResult(BaseModel):
    """
    Result of running one dataset case through the harness.
    """

    case_id: str
    passed: bool
    metrics: List[MetricResult] = Field(default_factory=list)
    failures: List[str] = Field(default_factory=list)
    app_output: AppOutput


class RunArtifact(BaseModel):
    """
    Final structured output of a full suite execution.
    """

    suite_name: str
    passed: bool
    results: List[CaseResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

#git issue