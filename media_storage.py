import sqlite3
import json
import os

media_db = 'data/media_storage.db'

def initialize_media_db():
    os.makedirs(os.path.dirname(media_db), exist_ok=True)
    with sqlite3.connect(media_db) as con:
        cur = con.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS media_data (video_hash TEXT PRIMARY KEY, media_info TEXT NOT NULL)'
        )
        con.commit()

def update_media_db(video_hash, video_data):
    if isinstance(video_data, dict):
        media_info = json.dumps(video_data)
    else:
        media_info = video_data
    with sqlite3.connect(media_db) as con:
        cur = con.cursor()
        cur.execute(
            'INSERT OR REPLACE INTO media_data (video_hash, media_info) VALUES (?, ?)',
            (video_hash, media_info)
        )
        con.commit()

def load_media_db(video_hash):
    with sqlite3.connect(media_db) as con:
        cur = con.cursor()
        cur.execute('SELECT media_info FROM media_data WHERE video_hash = ?', (video_hash,))
        row = cur.fetchone()
        if row:
            try:
                return json.loads(row[0])
            except (TypeError, ValueError):
                return None
        return None
