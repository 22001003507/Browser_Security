from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


DB_PATH = Path(
    "security_evidence.db"
)


def init_database():

    connection = sqlite3.connect(
        DB_PATH
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            url TEXT,
            score REAL,
            classification TEXT,
            decision TEXT,
            indicators TEXT
        )
        """
    )

    connection.commit()
    connection.close()


def save_analysis(
    url: str,
    score: float,
    classification: str,
    decision: str,
    indicators: list[str],
):

    init_database()

    connection = sqlite3.connect(
        DB_PATH
    )

    connection.execute(
        """
        INSERT INTO analyses
        (
            timestamp,
            url,
            score,
            classification,
            decision,
            indicators
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            time.time(),
            url,
            score,
            classification,
            decision,
            json.dumps(
                indicators
            ),
        ),
    )

    connection.commit()
    connection.close()