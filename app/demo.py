"""Seed fictional data for a small, read-only hosted demo."""

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion import account_payload, iter_records
from app.models import Account


def seed_demo_accounts(db: Session, sample_path: Path) -> int:
    """Seed the sample CSV only when the demo account table is empty."""
    if db.scalar(select(Account.id).limit(1)) is not None:
        return 0

    seeded = 0
    for row_number, (row, error) in enumerate(
        iter_records(str(sample_path), sample_path.name), start=1
    ):
        if error:
            raise ValueError(f"Invalid demo sample data: {error}")
        if row is not None:
            db.add(Account(**account_payload(row, sample_path.name, row_number)))
            seeded += 1
    db.commit()
    return seeded
