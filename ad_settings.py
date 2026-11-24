"""Atomic writes for local AD browser settings (never passwords)."""

import json
import os
import tempfile
from pathlib import Path


CONFIG_DIRECTORY = Path.home() / ".config" / "ad-directory"


def write_settings(path, settings):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(settings, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
