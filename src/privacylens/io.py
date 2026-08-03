"""Supported file loading and safe output helpers."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

SUPPORTED_EXTENSIONS = {".csv", ".parquet", ".json", ".jsonl"}


def load_table(path: str | Path) -> pd.DataFrame:
    """Load a supported tabular file without changing source column names."""

    source = Path(path)
    suffix = source.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise ValueError(f"Unsupported file type '{suffix}'. Use one of: {allowed}")
    if suffix == ".csv":
        frame = pd.read_csv(source)
    elif suffix == ".parquet":
        frame = pd.read_parquet(source)
    elif suffix == ".jsonl":
        frame = pd.read_json(source, lines=True)
    else:
        frame = pd.read_json(source)
    if frame.empty:
        raise ValueError("The input contains no data rows")
    if len({str(column) for column in frame.columns}) != len(frame.columns):
        raise ValueError("Input columns must have unique names")
    return frame


def write_table(frame: pd.DataFrame, path: str | Path) -> Path:
    """Write a sanitized dataframe using the requested supported format."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = destination.suffix.lower()
    if suffix == ".csv":
        frame.to_csv(destination, index=False)
    elif suffix == ".parquet":
        frame.to_parquet(destination, index=False)
    elif suffix == ".jsonl":
        frame.to_json(destination, orient="records", lines=True)
    elif suffix == ".json":
        frame.to_json(destination, orient="records", indent=2)
    else:
        raise ValueError("Output must use .csv, .parquet, .json, or .jsonl")
    return destination
