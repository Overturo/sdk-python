"""Consent records captured outside Overturo's surfaces (201).

The Record API (create = capture + commit in one call, idempotent on your key),
the read, the batch import with its dry run, and the status read by the
subject reference you supplied (email or your own identifier).
"""

from .client import (
    commit_capture,
    create_record,
    create_record_async,
    import_records,
    import_records_async,
    retrieve_import,
    retrieve_import_async,
    retrieve_record,
    retrieve_record_async,
    status,
    status_async,
)

__all__ = [
    "create_record",
    "create_record_async",
    "retrieve_record",
    "retrieve_record_async",
    "commit_capture",
    "import_records",
    "import_records_async",
    "retrieve_import",
    "retrieve_import_async",
    "status",
    "status_async",
]
