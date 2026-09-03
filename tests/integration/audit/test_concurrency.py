from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.services.audit.ledger import AsyncAuditLedger, AuditLedger

from tests.conftest import AuditFixture, draft


@pytest.mark.parametrize("attempt", range(3))
def test_parallel_append_assigns_unique_contiguous_ordinals(
    audit_fixture: AuditFixture,
    attempt: int,
) -> None:
    del attempt
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(audit_fixture.append_index, range(32)))

    assert sorted(receipt.ordinal for receipt in receipts) == list(range(1, 33))
    assert audit_fixture.verify().valid is True


@pytest.mark.asyncio
async def test_async_ledger_delegates_through_run_sync_without_committing(
    audit_fixture: AuditFixture,
) -> None:
    factory = AsyncUnitOfWorkFactory(audit_fixture.database.engine)
    ledger = AsyncAuditLedger(AuditLedger("audit-v1", b"K" * 32, audit_fixture.clock))

    try:
        async with factory() as uow:
            await ledger.append(uow, draft(40))

        assert audit_fixture.verify().count == 0

        async with factory() as uow:
            receipt = await ledger.append(uow, draft(41))
            await uow.commit()

        assert receipt.ordinal == 1
        assert audit_fixture.verify().count == 1

        async with factory() as uow:
            await ledger.append(uow, draft(42))
            segment = await ledger.seal(uow, 1, 2)
            await uow.commit()

        assert (segment.first_ordinal, segment.last_ordinal, segment.receipt_count) == (1, 2, 2)
        assert audit_fixture.verify().valid is True
    finally:
        await factory.aclose()
