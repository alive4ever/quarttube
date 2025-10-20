import sqlite3
from typing import Optional

db_path = 'data/captions.db'

def initialize_captions_db() -> None:
    with sqlite3.connect(db_path) as con:
        cur = con.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS subtitles ('
            'video_hash TEXT NOT NULL, '
            'lang TEXT NOT NULL, '
            'subtitle_content TEXT NOT NULL, '
            'PRIMARY KEY (video_hash, lang)'
            ')'
        )

def save_subtitle(video_hash: str, language: str, content: str) -> None:
    with sqlite3.connect(db_path) as con:
        cur = con.cursor()
        cur.execute(
            'INSERT OR REPLACE INTO subtitles (video_hash, lang, subtitle_content) VALUES (?, ?, ?)',
            (video_hash, language, content)
        )
        con.commit()

def load_subtitle(video_hash: str, language: str) -> Optional[str]:
    with sqlite3.connect(db_path) as con:
        cur = con.cursor()
        cur.execute(
            'SELECT subtitle_content FROM subtitles WHERE video_hash = ? AND lang = ?',
            (video_hash, language)
        )
        row = cur.fetchone()
        return row[0] if row is not None else None
