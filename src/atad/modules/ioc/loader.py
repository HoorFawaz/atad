# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Load an IOC list into a case: copy it (hashed, read-only), then parse it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from atad.cases.manager import OpenCase
from atad.core.exceptions import ValidationError
from atad.core.execution import import_file
from atad.evidence.models import Confidence, Execution, ExecutionStatus, Ioc, SourceModule
from atad.modules.ioc.parser import ParseReport, parse_file


@dataclass
class IocLoad:
    source: str
    execution: Execution
    report: ParseReport
    iocs: list[Ioc]
    added: int


def load_ioc_file(oc: OpenCase, src: Path, *, name: str | None = None,
                  confidence: Confidence = Confidence.MEDIUM) -> IocLoad:
    if src.is_dir():
        raise ValidationError("the IOC list must be a file, not a folder")
    rec = import_file(oc, module=SourceModule.IOC, tool="atad-ioc", source=src)
    if rec.execution.status is not ExecutionStatus.SUCCESS or rec.raw_path is None:
        raise ValidationError(f"could not copy {src}: {rec.execution.error}")
    report = parse_file(rec.raw_path)
    source = name or src.name
    iocs = [Ioc(case_id=oc.case.id, type=p.type, value=p.value, source=source,
                confidence=p.confidence or confidence, description=p.description)
            for p in report.iocs]
    return IocLoad(source, rec.execution, report, iocs, oc.repo.add_iocs(iocs))
