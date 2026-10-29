from collections.abc import Iterable
from enum import StrEnum


class Truth(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


def tri_not(value: Truth) -> Truth:
    return {Truth.TRUE: Truth.FALSE, Truth.FALSE: Truth.TRUE, Truth.UNKNOWN: Truth.UNKNOWN}[value]


def tri_all(values: Iterable[Truth]) -> Truth:
    found_unknown = False
    found_value = False
    for value in values:
        found_value = True
        if value is Truth.FALSE:
            return Truth.FALSE
        found_unknown |= value is Truth.UNKNOWN
    if not found_value or found_unknown:
        return Truth.UNKNOWN
    return Truth.TRUE


def tri_any(values: Iterable[Truth]) -> Truth:
    found_unknown = False
    found_value = False
    for value in values:
        found_value = True
        if value is Truth.TRUE:
            return Truth.TRUE
        found_unknown |= value is Truth.UNKNOWN
    if not found_value or found_unknown:
        return Truth.UNKNOWN
    return Truth.FALSE
