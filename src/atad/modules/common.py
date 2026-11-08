# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Helpers shared by the module runners."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from atad.adapters.base import ParseContext
from atad.cases.manager import OpenCase
from atad.core.execution import execute_collector, record_skipped
from atad.evidence.models import (
    CollectionMode,
    Evidence,
    Execution,
    ExecutionStatus,
    SourceModule,
)

EXCLUDED_BY_USER = "excluded_by_user"


@dataclass
class CheckOutcome:
    check: str
    execution: Execution
    evidence: list[Evidence] = field(default_factory=list)
    capture: dict[str, Any] | None = None

    @property
    def excluded_by_user(self) -> bool:
        return self.execution.error == EXCLUDED_BY_USER


def skip_check(case: OpenCase, *, module: SourceModule, check: str, tool: str,
               mode: CollectionMode, status: ExecutionStatus, reason: str,
               target: str | None = None) -> CheckOutcome:
    ex = record_skipped(case, module=module, tool=tool, collection_mode=mode,
                        status=status, reason=reason, target=target)
    return CheckOutcome(check, ex)


def run_collector_check(
    case: OpenCase,
    *,
    module: SourceModule,
    check: str,
    tool: str,
    tool_version: str | None,
    mode: CollectionMode,
    host: str,
    host_declared: bool = False,
    target: str | None = None,
    collect: Callable[[], dict],
    to_evidence: Callable[[dict, ParseContext], list[Evidence]],
) -> CheckOutcome:
    """Run an in-process collector, save its raw JSON, store its evidence."""
    rec = execute_collector(
        case, module=module, tool=tool, tool_version=tool_version, collection_mode=mode,
        target=target, description=[check] + ([target] if target else []),
        collect=lambda: json.dumps(collect(), ensure_ascii=False, indent=2, default=str).encode("utf-8"),
    )
    outcome = CheckOutcome(check, rec.execution)
    if rec.raw is not None:
        capture = json.loads(rec.raw)
        ctx = ParseContext(
            case_id=case.case.id, host=host, collection_mode=mode, host_declared=host_declared,
            execution_id=rec.execution.id, raw_ref=rec.execution.raw_ref,
            raw_sha256=rec.execution.raw_sha256, tool_version=tool_version,
            simulated=case.case.simulated, tool=tool,
        )
        outcome.capture = capture
        outcome.evidence = case.repo.add_evidence_many(to_evidence(capture, ctx))
    return outcome


def base_fields(ctx: ParseContext, module: SourceModule, tool: str) -> dict[str, Any]:
    """Common Evidence fields from a parse context."""
    return {
        "case_id": ctx.case_id, "source_module": module, "source_tool": tool,
        "tool_version": ctx.tool_version, "collection_mode": ctx.collection_mode,
        "host": ctx.host, "host_declared": ctx.host_declared, "execution_id": ctx.execution_id,
        "raw_ref": ctx.raw_ref, "raw_sha256": ctx.raw_sha256, "simulated": ctx.simulated,
    }
