from __future__ import annotations

from sqlalchemy import MetaData, Table

from .foundation_0001 import FOUNDATION_0001_METADATA, FOUNDATION_TABLE_NAMES

metadata = MetaData()
for _frozen_table in FOUNDATION_0001_METADATA.sorted_tables:
    _frozen_table.to_metadata(metadata)

# These names are stable imports for repositories. Future revisions add only
# their own tables to ``metadata`` and never mutate the 0001 snapshot.
globals().update({name: metadata.tables[name] for name in sorted(FOUNDATION_TABLE_NAMES)})

__all__ = ["metadata", *sorted(FOUNDATION_TABLE_NAMES)]

# Give static analyzers a useful declaration for the dynamically exported
# tables without making a second table collection.
_application_tables: tuple[Table, ...] = tuple(metadata.sorted_tables)
