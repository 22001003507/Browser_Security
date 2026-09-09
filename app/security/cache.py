from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path


DB_PATH = Path("security_cache.db")

CACHE_SECONDS = 3600


def _hash_url(url: str):

    return hashlib.sha256(
        url.strip().lower().encode()
    ).hexdigest()


def init_cache():

    connection = sqlite3.connect(
        DB_PATH
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS cache (
            url_hash TEXT PRIMARY KEY,
            url TEXT,
            score REAL,
            classification TEXT,
            created REAL
        )
        """
    )

    connection.commit()
    connection.close()


def get_cached(url: str):

    init_cache()

    connection = sqlite3.connect(
        DB_PATH
    )

    row = connection.execute(
        """
        SELECT score, classification, created
        FROM cache
        WHERE url_hash = ?
        """,
        (_hash_url(url),),
    ).fetchone()

    connection.close()

    if not row:
        return None

    score, classification, created = row

    if time.time() - created > CACHE_SECONDS:
        return None

    return {
        "score": score,
        "classification": classification,
    }


def save_cache(
    url: str,
    score: float,
    classification: str,
):

    init_cache()

    connection = sqlite3.connect(
        DB_PATH
    )

    connection.execute(
        """
        INSERT OR REPLACE INTO cache
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            _hash_url(url),
            url,
            score,
            classification,
            time.time(),
        ),
    )

    connection.commit()
    connection.close()