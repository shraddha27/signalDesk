from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import account_detail, list_accounts, overview
from app.models import Account, Base


def test_account_search_detail_and_overview_use_persisted_records():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Account(
                    account_key="northstar",
                    name="Northstar Health",
                    domain="northstar.example",
                    industry="Healthcare",
                    country="US",
                    employee_count=420,
                    score=70,
                    tier="high",
                    signals=[{"title": "Security incident", "points": 35}],
                    attributes={"news": "Ransomware incident"},
                    source_file="companies.csv",
                    updated_at=datetime.now(timezone.utc),
                ),
                Account(
                    account_key="plain",
                    name="Plain Retail",
                    score=0,
                    tier="low",
                    signals=[],
                    attributes={},
                    source_file="companies.csv",
                    updated_at=datetime.now(timezone.utc),
                ),
            ]
        )
        db.commit()

        result = list_accounts(
            q="health",
            industry=None,
            tier=None,
            min_score=0,
            sort="score",
            limit=50,
            offset=0,
            db=db,
        )
        detail = account_detail(result["items"][0]["id"], db=db)
        summary = overview(db=db)

    assert result["total"] == 1
    assert result["items"][0]["name"] == "Northstar Health"
    assert detail["signals"][0]["title"] == "Security incident"
    assert summary["total_accounts"] == 2
    assert summary["high_priority_accounts"] == 1
