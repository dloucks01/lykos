"""DM-11 — Base repository utilities.

Shared JSON (de)serialization and a small BaseDAO. Row→dataclass mapping is done
explicitly per entity in dao.py (clearer and safer than reflection, given JSON/bool cols).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional


def dumps(obj: Any) -> Optional[str]:
    return None if obj is None else json.dumps(obj, ensure_ascii=False)


def loads(s: Optional[str]) -> Any:
    return None if s in (None, "") else json.loads(s)


def as_bool(v: Any) -> Optional[bool]:
    return None if v is None else bool(v)


def as_flag(v: Any) -> bool:
    """Read a nullable INTEGER bool column into a non-null flag.

    Some bool columns (dyn_result.crashed, poc.verified, ...) are nullable in SQL but their
    dataclass field is a plain `bool` defaulting to False. NULL means "never recorded", which
    is the same as False here -- collapse it at the read boundary so None never reaches the
    model (and never surfaces as `null` in the JSON API).
    """
    return bool(v)


def as_int_bool(v: Optional[bool]) -> Optional[int]:
    return None if v is None else int(v)


class BaseDAO:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
