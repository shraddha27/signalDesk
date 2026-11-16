import asyncio
from io import BytesIO

import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import main
from app.demo import seed_demo_accounts
from app.models import Account, Base


def test_demo_seeds_fictional_accounts_once(tmp_path):
    source = tmp_path / "sample_accounts.csv"
    source.write_text(
        "company_name,domain,industry,country,employee_count,news\n"
        "Demo Health,demo-health.example,Healthcare,US,100,Ransomware incident\n"
        "Demo Retail,demo-retail.example,Retail,US,20,New location\n",
        encoding="utf-8",
    )
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        assert seed_demo_accounts(db, source) == 2
        assert seed_demo_accounts(db, source) == 0
        accounts = db.scalars(select(Account).order_by(Account.name)).all()
        assert [account.name for account in accounts] == ["Demo Health", "Demo Retail"]
        assert accounts[0].score > accounts[1].score

    engine.dispose()


def test_demo_mode_hides_upload_capability_and_rejects_uploads(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)

    assert main.public_config() == {"demo_mode": True, "uploads_enabled": False}
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            main.upload_ingestion(
                file=UploadFile(filename="sample.csv", file=BytesIO(b"data")),
                db=None,
            )
        )
    assert error.value.status_code == 503
