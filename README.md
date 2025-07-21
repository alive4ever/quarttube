# QuartTube

*A lightweight video watch page built with Python, httpx, yt-dlp, and Quart ASGI.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

A minimal, self-hosted video watch page that allows users to stream content from YT and other platforms without distractions.

The main feature is to get a clean watch page for a video. Imagine browsing some video-on-demand site on mobile and be asked to install 100MB+ app to view a video. It is uncacceptable, isn'it?

QuartTube solves the frustrating problem of being forced to download massive mobile apps just to watch a video. It provides a lightweight, privacy-focused video streaming solution that works across multiple platforms.


---

## Features

- 🚀 **Distraction-Free Viewing**: Clean, minimal interface without unnecessary bloat
- 🔒 **Privacy-First**: Stream without invasive app permissions
- 💻 **Cross-Platform**: Works on desktop and mobile
- 🌐 **Multi-Platform Support**: YT, Bilibili, Nicovideo.

---

## Tech Stack

- **Backend**: Python, Quart, httpx
- **Video scraping**: yt-dlp  
- **Frontend**: HTML/CSS, with `hls.js` and `dash.js` for in-browser video playback

---

## Tested video-on-demand platforms

- Nicovideo.jp (hls)
- bilibili.com and bilibili.tv (dash)
- YT (hls/dash)

## Installation

```bash
# Use a virtual environment at home directory
python3 -m venv ./venv
. ./venv/bin/activate

# Clone the repo
git clone https://github.com/alive4ever/quarttube.git
cd quarttube

# Install dependencies
pip install -r requirements.txt

# Install patched yt-dlp to enable dash bilibili playback
git clone --depth=1 https://github.com/yt-dlp/yt-dlp
cd yt-dlp
git apply ../ytdlp_bili_segment_base.patch
pip install .
cd ..

# Optional dependency
pip install mediaflow-proxy

# Recommended dependency, for faster YT video info extraction
pip install git+https://github.com/alive4ever/yt-dlp-YTNSigDukpy.git

```

---

## Running

```bash
# Load virtual environment
. ~/venv/bin/activate
# Using uvicorn
uvicorn --reload --reload-include 'data/settings.ini' --host localhost --port 5000 quarttube:app
# Using gunicorn
gunicorn --reload-extra-file 'data/settings.ini' --reload -k uvicorn_worker.UvicornWorker -b localhost:5000 quarttube:app
# Using hypercorn + watchfiles
watchfiles 'hypercorn -b localhost:5000 quarttube:app' 'data/settings.ini'

```

An example `start.sh` script to launch the app is available in the project directory.

The web frontend is accessible on `http://localhost:5000`, with several accessible endpoints.

- `/bilisearch`: simple BiliBili search page.
- `/nicosearch`: simple Nicovideo search page.
- `/ytsearch`: simple YT search page.
- `/settings`: configuration page.


### Integration with mediaflow-proxy

`mediaflow-proxy` was used extensively during development before the `/stream` endpoint handles `m3u8` hls manifest. It provides an easy-to-use `/proxy` endpoint to route stream. It is now an optional dependency.

To use it with `mediaflow-proxy`, an instance of `mediaflow-proxy` has to be started separately. Then, enable `use_mediaflow` and adjust `mediaflow_instance` in the `/settings` page.

## Deployment

Example `nginx.conf` snippet for deployment under `quarttube` on Debian.

```
location /quarttube {
	return 302 $scheme://$host/quarttube/;
}

location /quarttube/ {
	proxy_pass http://localhost:5000/;
	include proxy_params;
	sub_filter '"/"' '"/quarttube/"';
	sub_filter '"/stream' '"/quarttube/stream';
	sub_filter_once off;
	add_header Access-Control-Allow-Origin '*';
	add_header Content-Security-Policy "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net";
	add_header Referrer-Policy 'same-origin';
	add_header X-Powered-By 'uvicorn';
}

location ~ ^/(video|audio|hls|dash|stream|subtitle|view_page|proxy)(.*)$ {
	rewrite ^/(.*) /quarttube/$1 last;
}

```


## License

Licensed under the MIT License.

