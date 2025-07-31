import configparser
from quart import Quart, request, Response, redirect, abort, render_template, make_response, url_for, jsonify, flash
from werkzeug.http import remove_hop_by_hop_headers
import subprocess
import httpx
import http.cookiejar
import urllib.parse
from markupsafe import escape, Markup
import os
import re
import yt_dlp
from yt_dlp.extractor.youtube._base import INNERTUBE_CLIENTS
import json
import base64
import asyncio
import hashlib
import logging
import random
import blackboxprotobuf

class JSONStorage:
    def __init__(self, filename):
        self.filename = filename
        self._lock = asyncio.Lock()

    async def write(self, data):
        async with self._lock:
            with open(self.filename, 'w') as f:
                json.dump(data, f)

    async def read(self):
        async with self._lock:
            try:
                with open(self.filename, 'r') as f:
                    return json.load(f)
            except FileNotFoundError:
                return {}

    async def update(self, update_dict):
        async with self._lock:
            try:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
            except FileNotFoundError:
                data = {}
            
            # Update the entire dictionary
            data.update(update_dict)
            
            with open(self.filename, 'w') as f:
                json.dump(data, f)

logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'  # Custom date format
)

logger = logging.getLogger(__name__)
logger.level = logging.INFO

try:
    from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url
    mediaflow_import = True
except ImportError:
    mediaflow_import = False
    logger.warning('Importing mediaflow_proxy failed. Not using mediaflow_proxy for this session')
    pass

app = Quart(__name__)

# Get value of known key in a nested dict
def find_by_key(data, target_key):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == target_key:
                return value
            result = find_by_key(value, target_key)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data:
            result = find_by_key(item, target_key)
            if result is not None:
                return result
    return None

app_config = configparser.ConfigParser()

default_value = ({
        'stream': 
        { 'use_mediaflow': False,
          'mediaflow_instance': 'http://localhost:8088',
         },
        'playback':
        { 'use_dash_js': True,
          'video_height': 360,
          'show_subtitle': False,
          'use_innertube_subtitle': True,
          'sub_lang': 'en',
        },
        'logging':
        { 'log_level': 'INFO' },
    })
def get_config():
    default_config = dict(default_value)
    conf_file = 'data/settings.ini'
    if not os.path.isdir('data'):
        logger.info('Creating data directory')
        os.makedirs('data')
    try:
        with open(conf_file, 'r') as file:
            app_config.read_file(file)
    except Exception as err:
        logger.debug(f"Unable to load configuration file. Using default config.\n{err}")
        default = app_config.read_dict(default_config)
        with open(conf_file, 'w') as file:
            logger.info('Saving default config')
            app_config.write(file)
        return default

def generate_mediaflow_url(dest_url, headers: dict):
    if not use_mediaflow:
        return None
    elif not mediaflow_import:
        return None
    mediaflow_instance = 'http://dummy'
    endpoint = '/proxy/stream'
    if 'm3u8' in dest_url:
        endpoint = '/proxy/hls/manifest.m3u8'
    mediaflow_dummy_url = encode_mediaflow_proxy_url(mediaflow_proxy_url=mediaflow_instance, endpoint=endpoint, destination_url=dest_url, request_headers=headers)
    mediaflow_url = mediaflow_dummy_url.replace(mediaflow_instance, '')
    return mediaflow_url

def get_stream_url(url, headers: dict = {}):
    url_base64 = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8')
    stream_qs = { 'media_url': url_base64 }
    if headers:
        headers_base64 = base64.urlsafe_b64encode(json.dumps(headers).encode('utf-8'))
        stream_qs['headers'] = headers_base64
    stream_url = f"/stream?{urllib.parse.urlencode(stream_qs)}"
    return stream_url

def get_base_url(url):
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.hostname}{os.path.dirname(parsed_url.path)}"
    return base_url

async def get_proxied_m3u8(playlist, playlist_url, proxy_function, headers: dict = {}):
    base_url = get_base_url(playlist_url)
    url_pattern = re.compile(r'(?m)URI="([^"]+?)"')
    new_lines = []
    for line in playlist.splitlines():
        if line:
            if line.startswith('#'):
                url_match = url_pattern.search(line)
                if url_match:
                    url = url_match.group(1)
                    if url.startswith('http'):
                        full_url = url
                    else:
                        full_url = urllib.parse.urljoin(base_url, url)
                    new_url = proxy_function(full_url, headers)
                    new_line = url_pattern.sub(f'URI="{new_url}"', line)
                else:
                    new_line = line
            elif line.startswith('http'):
                new_line = proxy_function(line, headers)
            else:
                full_url = urllib.parse.urljoin(base_url, line)
                new_line = proxy_function(full_url, headers)
            new_lines.append(new_line)
    return '\n'.join(new_lines)

def localize_url(url: str, headers: dict = {}):
    quoted_url = urllib.parse.quote(url)
    base64_url = base64.urlsafe_b64encode(quoted_url.encode('utf-8')).decode()
    if headers:
        headers_base64 = base64.urlsafe_b64encode(json.dumps(headers).encode('utf-8'))
        qs =  { 'headers': headers_base64 }
        query_string = urllib.parse.urlencode(qs)
        full_url = f"/stream/{base64_url}?{query_string}"
    else:
        full_url = f"/stream/{base64_url}"
    return full_url

def proxify_url(url, headers: dict = {}):
    proxy_base = '/stream/hls'
    proxy_data = { 'dest': url }
    if headers:
        hdr_param = {}
        for k,v in headers.items():
            hdr_param[f"h_{k}"] = v
        proxy_data.update(hdr_param)
    proxied_url = proxy_base + '?' + urllib.parse.urlencode(proxy_data)
    return proxied_url

def decode_proxified_url(url):
    proxy_base = '/stream/hls'
    parsed_url = urllib.parse.urlparse(url)
    proxy_data = urllib.parse.parse_qs(parsed_url.query)
    req_hdr = {}
    for k, v in proxy_data.items():
        if k.startswith('h_'):
            req_hdr[k.replace('h_', '')] = v[0]
    reconstructed_url = proxy_data.get('dest')[0]
    return reconstructed_url, req_hdr

cookiejar = http.cookiejar.MozillaCookieJar(filename='data/cookies.txt')
try:
    cookiejar.load()
    logger.info("Cookies loaded successfully")
    cookiejar.clear_expired_cookies()
except Exception as err:
    logger.warning("Unable to load cookiejar")
    logger.debug(f"Traceback:\n{err}")
    pass

async def get_ytcfg():
    client = httpx.AsyncClient(http2=True, follow_redirects=True, headers=desktop_headers, cookies=cookiejar)
    ytcfg_file = 'data/ytcfg.json'
    if not os.path.isfile(ytcfg_file):
        youtube = 'https://www.youtube.com'
        home_resp = await client.get(youtube)
        ytcfg_re = r'ytcfg\.set\(({.+?})\)'
        ytcfg_match = re.search(re.compile(ytcfg_re), home_resp.text)
        ytcfg = json.loads(ytcfg_match.group(1))
        forbidden_item = [ 'remoteHost', 'configInfo', 'rolloutToken', 'deviceExperimentId' ]
        for item in forbidden_item:
            if ytcfg['INNERTUBE_CONTEXT']['client'].get(item):
                logger.debug(f'Removing {item} from ytcfg')
                ytcfg['INNERTUBE_CONTEXT']['client'].pop(item)
        if ytcfg['INNERTUBE_CONTEXT'].get('clickTracking'):
            logger.debug('Removing clickTracking from ytcfg')
            ytcfg['INNERTUBE_CONTEXT'].pop('clickTracking')

        logger.info('Saving ytcfg to cache')
        with open(ytcfg_file, 'w') as file:
            json.dump(ytcfg, file)
        return ytcfg
    else:
        with open(ytcfg_file, 'r') as file:
            logger.info('Loading ytcfg from cache')
            ytcfg = json.load(file)
        return ytcfg

async def show_error_page(status, message, details=''):
    return await render_template('error_page.html', status=status, message=message, error_details=details, log_level=log_level)

get_config()
# App configuration
if mediaflow_import:
    use_mediaflow = app_config['stream'].getboolean('use_mediaflow', False)
else:
    use_mediaflow = False
    app_config['stream']['use_mediaflow'] = str(use_mediaflow)
mediaflow_instance = app_config['stream'].get('mediaflow_instance')
video_height = app_config['playback'].getint('video_height')
use_dash_js = app_config['playback'].getboolean('use_dash_js')
show_subtitle = app_config['playback'].getboolean('show_subtitle', False)
use_innertube_subtitle = app_config['playback'].getboolean('use_innertube_subtitle', True)
sub_lang = app_config['playback'].get('sub_lang', 'en')
log_level = app_config['logging'].get('log_level', 'INFO')
logger.debug(f"Mediaflow: {use_mediaflow}, Mediaflow instance: {mediaflow_instance}, Video height: {video_height}, Use dash: {use_dash_js}, Show subtitle: {show_subtitle}, Subtitle language: {sub_lang}, Log level: {log_level}")
logger.setLevel(log_level)

desktop_headers_dict = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': 1,
            'Sec-GPC': 1,
            'Upgrade-Insecure-Requests': 1,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i',
            }

def normalize_headers(headers):
    normalized_headers = {}
    for k, v in headers.items():
        if not isinstance(v, str):
            v_str = str(v)
        else:
            v_str = v
        normalized_headers[k] = v_str
    return normalized_headers

desktop_headers = normalize_headers(desktop_headers_dict)
async_client = httpx.AsyncClient(headers=desktop_headers, http2=True, follow_redirects=True, cookies=cookiejar)
appended_headers = { 'Access-Control-Allow-Origin': '*',
                "Access-Control-Allow-Methods": "*",
                "Accept-Ranges": "bytes",
                        }

def normalize_url(url):
    missing_slash_re = re.compile(r'(https?:/)(\w)')
    missing_slash = re.search(missing_slash_re, url)
    if missing_slash:
        logger.debug("Fixing missing slash in the url")
        normalized_url = re.sub(missing_slash_re, r'\1/\2', url)
        return normalized_url
    else:
        return url

async def head(url, session_client=async_client, headers={}):
    if headers:
        req_headers = headers
    else:
        req_headers = desktop_headers
    server_response = await session_client.request('HEAD', url, headers=req_headers)
    status_code = server_response.status_code
    try:
        server_response.raise_for_status()
    except Exception as err:
        logger.error(f'Got non 200 http response doing head\n{err}')
        return status_code, {}
    await server_response.aclose()
    return status_code, server_response.headers

async def streaming(url, session_client=async_client, headers={}):
    parsed_url = urllib.parse.urlparse(url)
    logger.debug(f"Streaming response for {parsed_url.hostname}")
    async with session_client.stream('GET', url, headers=headers) as resp:
        resp.raise_for_status()
        status_code = resp.status_code
        server_headers = resp.headers
        async for chunk in resp.aiter_bytes(32*1024):
            if chunk:
                yield chunk

async def get_content_length(url, session_client=async_client, headers={}):
    if headers:
        req_headers = desktop_headers
    else:
        req_headers = headers
    resp_status, resp_headers = await head(url, session_client, headers=req_headers)
    length = resp_headers.get('Content-Length', 0)
    return length

async def streaming_with_retries(url, session_client=async_client, headers={}):
    parsed_url = urllib.parse.urlparse(url)
    logger.debug(f"Streaming with retries for {parsed_url.hostname}")
    downloaded_bytes = 0
    max_retries = 5
    retry_delay = 1
    content_length = await get_content_length(url, session_client, headers)
    if not isinstance(content_length, int):
        content_length = int(content_length)
    retries = 0
    range_header = [ v for k, v in headers.items() if k.lower() == 'range' ]
    if range_header:
        logger.debug('Range request detected')
        range_header_value = range_header.split('=')[-1]
        start_byte = int(range_header_value.split('-')[0])
        end_byte = range_header_value.split('-')[1] or content_length
        if not isinstance(end_byte, int):
            end_byte = int(end_byte)
        downloaded_bytes = start_byte

    if content_length > 0:
        while retries <= max_retries and downloaded_bytes < content_length:
            if retries > 0 and content_length > 0 and downloaded_bytes < content_length:
                logger.info(f"Retrying num: {retries} at {downloaded_bytes} of {content_length}")
                if downloaded_bytes >= content_length:
                    break

            if range_header:
                logger.debug(f'Serving range of {start_byte} to {end_byte}')
                if downloaded_bytes >= end_byte:
                    logger.debug("Serving range completed")
                    break
            try:
                async with session_client.stream('GET', url, headers=headers) as r:
                    r.raise_for_status()
                    status_code = r.status_code
                    server_headers = r.headers
                    if range_header and not server_headers.get('Content-Range'):
                        server_headers['Content-Range'] = f"bytes {start_byte}-{end_byte}/{content_length}"

                    async for chunk in r.aiter_bytes(32*1024):
                        if chunk:
                            downloaded_bytes += len(chunk)
                            yield chunk
                    retries = 0
                    if content_length > 0 and downloaded_bytes >= content_length:
                        break

            except (httpx.HTTPStatusError, httpx.NetworkError, httpx.RequestError, httpx.RemoteProtocolError, httpx.ReadTimeout) as e:
                if content_length > 0 and downloaded_bytes < content_length:
                    retries += 1
                    logger.warning(f'An error occurred at {downloaded_bytes}')
                    await asyncio.sleep(retry_delay)
                else:
                    break
            except Exception as err:
                status_code = 500
                logger.error(f'An unexpected error occured\n{err}')
                break

async def non_streaming(url, session_client=async_client, headers={}):
    parsed_url = urllib.parse.urlparse(url)
    logger.debug(f"Performing non streaming request for {parsed_url.hostname}")
    range_header = [ v for k, v in headers.items() if k.lower() == 'range' ]
    if range_header:
        range_value = range_header[0].split('=')[-1]
        start_byte, end_byte = range_value.split('-')
        if not end_byte:
            end_byte = await get_content_length(url, session_client, headers)
        logger.debug(f"Serving range request from {start_byte} to {end_byte} for {parsed_url.hostname}")
    headers_orig = headers
    try:
        resp = await session_client.get(url, headers=headers)
        resp.raise_for_status()
    except Exception as err:
        logger.error(f'Got non 200 status for {parsed_url.hostname}\n{err}')
        return await show_error_page('Request error', 'Got non successful response from upstream', f'Traceback:\n{err}'), 500
    content = await resp.aread()
    status_code = resp.status_code
    content_type = resp.headers.get('Content-Type')
    resp_hdrs = dict(resp.headers)
    resp_hdrs.update(appended_headers)
    hls_endings = ['m3u8', 'm3u']
    is_hls = parsed_url.path.split('.')[-1] in hls_endings
    if is_hls and content_type.lower().endswith('mpegurl'):
        logger.debug(f"Performing m3u8 proxying for {parsed_url.hostname}")
        manifest_orig = content.decode('utf-8')
        if len(manifest_orig) == 0:
            logger.error(f'Got zero length response from {parsed_url.hostname}')
            return await show_error_page('Unexpected Response', f'Got zero length response from {parsed_url.hostname}', 'The upstream responded with zero length response'), 404
        transformed_manifest = await get_proxied_m3u8(manifest_orig, url, proxify_url, headers )
        content = transformed_manifest.encode('utf-8')
        allowed_headers = [ 'content-type' ]
        resp_hdrs_keys = list(resp_hdrs.keys())
        for k in resp_hdrs_keys:
            if k.lower() not in allowed_headers:
                resp_hdrs.pop(k)
        resp_hdrs['Content-Length'] = int(len(content))
        resp_hdrs['Content-Disposition'] = 'inline'
    await resp.aclose()
    return content, status_code, resp_hdrs

#Video info extraction
def get_video_info(video_url, wanted_format):
    ydl_opts = {
        'extractor_args': {
        },
        'format': wanted_format,
        'cookies': 'data/cookies.txt',
    }

    if log_level == 'DEBUG':
        ydl_opts.update({'verbose': True})
    elif log_level == 'ERROR':
        ydl_opts.update({'quiet': True})

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(video_url, download=False)
        video_info = {
            'formats': info.get('formats'),
            'subtitles': info.get('subtitles'),
            'requested_formats': info.get('requested_formats'),
            'thumbnail': info.get('thumbnail'),
            'title': Markup(info.get('title', 'No title available')).unescape(),
            'description': Markup(info.get('description', 'No description available')).unescape(),
            'duration': info.get('duration'),
            'duration_string': info.get('duration_string'),
        }
        return video_info

def get_period_mpd(seconds):
    if not isinstance(seconds, int):
        int_time = int(seconds)
    else:
        int_time = seconds
    hh = int_time // 3600
    mm = int_time // 60
    ss = int_time % 60
    mpd_period = f"{hh:02}H{mm:02}M{ss:02}S"
    return mpd_period

def get_period_text(seconds):
    if not isinstance(seconds, int):
        int_time = int(seconds)
    else:
        int_time = seconds
    hh = int_time // 3600
    mm = int_time // 60
    ss = int_time % 60
    if hh > 0:
        time_text = f'{hh:02}:{mm:02}:{ss:02}'
    else:
        time_text = f'{mm:02}:{ss:02}'
    return time_text

def genrandom_secret_base64(num_bytes):
    random_bytes = random.randbytes(num_bytes)
    random_base64 = base64.b64encode(random_bytes).decode()
    return random_base64
# Subtitle functions
def generate_caption_params(video_id: str = '', lang: str = 'en', auto_generated: bool = False):
    typedef_2 = {
            '1': {
                'name': 'kind',
                'type': 'string',
                },
            '2': {
                'name': 'language_code',
                'type': 'string',
                },
            '3': {
                'name': 'empty_string',
                'type': 'string',
                },
            }

    typedef = {
            '1': {
                'name': 'videoId',
                'type': 'string',
                },
            '2': {
                'name': 'lang_param',
                'type': 'string',
                },
            '3': {
                'name': 'varint_3',
                'type': 'int',
                },
            '5': {
                'name': 'fixed_string',
                'type': 'string',
                },
            '6': {
                'name': 'varint_6',
                'type': 'int',
                },

            '7': {
                'name': 'varint_7',
                'type': 'int',
                },
            '8': {
                'name': 'varint_8',
                'type': 'int',
                },
            }

    def encode_to_protobuf(message, typedef):
        result = blackboxprotobuf.encode_message(message, typedef)
        return result

    language_code = lang
    if not auto_generated:
        kind = ""
    else:
        kind = "asr"

    two_payload = {
            'kind': kind,
            'language_code': language_code,
            'empty_string': ''
    }

    two_protobuf = encode_to_protobuf(two_payload, typedef_2)
    base64_encoded_lang = base64.b64encode(two_protobuf).decode()
    one_payload = {
            'videoId': video_id,
            'lang_param': base64_encoded_lang,
            'varint_3': 1,
            'fixed_string': 'engagement-panel-searchable-transcript-search-panel',
            'varint_6': 0,
            'varint_7': 0,
            'varint_8': 0,
            }

    one_protobuf = encode_to_protobuf(one_payload, typedef)

    unquoted_params = base64.b64encode(one_protobuf).decode()
    params = urllib.parse.quote(unquoted_params)
    return params

async def post_subtitle_request(params):
    youtube_home = 'https://www.youtube.com'
    caption_api = f"{youtube_home}/youtubei/v1/get_transcript"
    ytcfg = await get_ytcfg()
    if ytcfg.get('INNERTUBE_API_KEY'):
        api_key = ytcfg['INNERTUBE_API_KEY']
        full_url = f'{caption_api}?key={api_key}'
    else:
        full_url = caption_api
    payload = { 'context': ytcfg['INNERTUBE_CONTEXT'], 'params': params }
    resp = await async_client.post(full_url, json=payload)
    resp.raise_for_status()
    content = await resp.aread()
    await resp.aclose()
    return content

async def extract_caption_segments_from_json(subtitle_data: {}, sub_lang: str = 'en'):
    body_part = find_by_key(subtitle_data['actions'][0], 'body')
    vtt_body = find_by_key(body_part, 'initialSegments')
    continuation_param = None
    if vtt_body:
        result = { 'caption_segments': vtt_body, 'continuation': None }
    else:
        footer = find_by_key(subtitle_data['actions'][0], 'footer')
        footer_submenu = find_by_key(footer, 'subMenuItems')
        for item in footer_submenu:
            if sub_lang in item['title'].lower():
                continuation_param = find_by_key(item['continuation'], 'continuation')
                if continuation_param:
                    logger.debug(f"Using continuation for subtitle {item['title']}")
                    break
        result = { 'continuation': continuation_param, 'caption_segments': None }
    return result

def test_continuation(caption_data):
    return caption_data.get('continuation')

def convert_milliseconds_to_hhmmss_optimized(ms):
    if not isinstance(ms, int):
        ms = int(ms)
    total_seconds = ms // 1000
    milliseconds = ms % 1000
    hours = total_seconds // 3600
    total_seconds %= 3600
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    return f"{hours:02}:{minutes:02}:{seconds:02}.{milliseconds:03}"

async def webvtt_from_caption_data(caption_data: dict = {}):
    if not caption_data:
        return None
    vtt_body = caption_data.get('caption_segments')
    if not vtt_body:
        return 'WEBVTT\n'

    vtt_content = [ 'WEBVTT\n' ]

    for item in vtt_body:
        if item.get('transcriptSegmentRenderer'):
            vtt_item = item['transcriptSegmentRenderer']
            ms_to_vtt_time = convert_milliseconds_to_hhmmss_optimized
            start_time = ms_to_vtt_time(vtt_item['startMs'])
            end_time = ms_to_vtt_time(vtt_item['endMs'])
            running_text = vtt_item['snippet']['runs'][0]['text']
            webvtt_time_line = str.format("""{} --> {}\n{}\n""", start_time, end_time, running_text)
            vtt_content.append(webvtt_time_line)

    vtt_txt = '\n'.join(vtt_content)
    return vtt_txt

# dash fixup functions (to add missing initialization and index_range)
async def get_test_segment(url, headers={}):
    this_req_header = headers
    segment_headers = {"Range": f"bytes=0-{32*1024}"}
    this_req_header.update(segment_headers)
    init_segment_resp = await async_client.get(url, headers=this_req_header)
    init_segment_resp.raise_for_status()
    init_segment = await init_segment_resp.aread()
    await init_segment_resp.aclose()
    return init_segment

def find_sidx_moof_mp4(video_init_bytes):
    sidx_re = re.compile(br'.{4}sidx')
    moof_re = re.compile(br'.{5}moof')
    sidx_match = re.search(sidx_re, video_init_bytes)
    if sidx_match:
        sidx_start = sidx_match.start()
    moof_match = re.search(moof_re, video_init_bytes)
    if moof_match:
        moof_start = moof_match.start()
    init_range = f'0-{sidx_start-1}'
    index_range = f'{sidx_start}-{moof_start}'
    return init_range, index_range

app_secret_file = 'data/session_key.txt'
# Load/generate app secret key
try:
    with open(app_secret_file, 'r') as file:
        secret_key = file.read()
        app.secret_key = secret_key
        del secret_key
except Exception as err:
    logger.error('No app secret found, generating new app secret')
    logger.debug(f'Traceback:\n{err}')
    secret_key = genrandom_secret_base64(32)
    app.secret_key = secret_key
    logger.info('Saving app secret key')
    with open(app_secret_file, 'w') as file:
        file.write(secret_key)
    logger.info('Key saved successfully')
    del secret_key

# Initialize media data storage
media_json_storage = JSONStorage('data/media_storage.json')

@app.route("/")
async def index():
    return await render_template('index.html')

@app.route("/view", methods=['POST', 'GET'])
async def watch_redirect():
    if request.method == 'GET':
        video_id = request.args.get('v')
    else:
        form_data = await request.form
        video_id = escape(form_data.get('v'))
    if video_id:
        video_id_quoted = urllib.parse.quote(video_id)
        return redirect(f'view_page?v={video_id_quoted}')
    else:
        return show_error_page('No video_id given', 'You need to submit video id to be processed', 'The video_id is required'), 400

@app.route("/view_page")
async def video_page():
    video_id_quoted = request.args.get('v')
    video_id = urllib.parse.unquote(video_id_quoted)
    try:
        parsed_video_id = urllib.parse.urlparse(video_id)
    except Exception as err:
        logger.error(f'Traceback:\n{err}')
        return await show_error_page('Invalid url', 'Invalid url entered', f'Traceback:\n{err}'), 400
    video_site = parsed_video_id.hostname
    if video_site:
        video_domain = '.'.join(video_site.split('.')[-2:])
        logger.info(f'{video_site} detected')
    else:
        logger.error('Invalid domain given.')
        return await show_error_page('Invalid domain', 'Invalid url entered', 'A valid url is required'), 400
    default_format = f'bestvideo[height<={video_height}]+bestaudio'
    hls_format = f'bestvideo[height<={video_height}][protocol=m3u8_native]+bestaudio[protocol=m3u8_native]'
    v_height = f"{video_height}p"
    if 'bilibili' in video_domain:
        bilibili_video_formats = { '360p': 30016, '480p': 30032, '720p': 30064, '1080p': 30080 }
        bilibili_audio_formats = { '64k': 30216, '130k': 30232, '192k': 30280 }
        bilibili_format = f"{bilibili_video_formats.get(v_height)}+{bilibili_audio_formats.get('130k')}"
        selected_format = bilibili_format
        fallback_format = default_format
    elif 'youtu' in video_domain:
        yt_video_formats = { '360p': 134, '480p': 135, '720p': 136, '1080p': 137 }
        yt_audio_formats = { 'opus': 251, 'aac': 140 }
        alternative_format = f"{yt_video_formats.get(v_height)}+{yt_audio_formats.get('aac')}"
        selected_format = hls_format
        fallback_format = f'bestvideo[ext=mp4][height<={video_height}][protocol=https]+bestaudio[ext=m4a][protocol=https]'
    else:
        selected_format = hls_format
        fallback_format = default_format
    logger.debug(f"Selected format: {selected_format}, fallback format: {fallback_format}, default format: {default_format}")

    support_hls = [ 'nicovideo.jp', 'youtube.com', 'youtu.be' ]
    if video_domain in support_hls:
        selected_format = hls_format
    media = {}
    media_hash = hashlib.blake2s(video_id.encode('utf-8')).hexdigest()
    short_url_qs = urllib.parse.urlencode({'hash': media_hash })
    retry_delay = 5
    try:
        media_list = await media_json_storage.read()
        if media_list.get(media_hash):
            logger.info(f"Got media info from storage cache")
            media = media_list[media_hash]
    except Exception as err:
        logger.warning('Unable to accesss media storage')
        logger.debug(f'Traceback:\n{err}')
        pass
    if not media:
        format_missing = None
        yt_dlp_format = f'{selected_format}/{fallback_format}'
        video_content_info = {}
        try:
            video_content_info = await asyncio.to_thread(get_video_info, video_id, yt_dlp_format)
        except Exception as err:
            logger.error(f'Got an exception during metadata loading\n{err}')
            return await show_error_page('Video info extraction failed', 'Got an exception trying to extract video info', f'Unable to get video info for {video_id}.\nEither got rate limited or temporary blocked to access the service or unknown extractor backend error\nTraceback:\n{err}'), 500
        content_type = []
        requested_formats = video_content_info.get('requested_formats')
        if not requested_formats:
            availabe_format = []
            if video_content_info.get('formats'):
                for item in video_content_info['formats']:
                    format_line = item['format_id'] + ': ' + ', '.join( item['resolution'], item.get('vcodec', 'null'), item.get('acodec', 'null'), item['protocol'])
                    available_format.append(format_line)
                extracted_formats = '\n'.join(available_format)
            else:
                extracted_formats = None
            logger.error('Unable to get requested formats')
            logger.debug(f"Available formats:\n{extracted_formats}")
            return await show_error_page('Requested formats not found', 'Unable to get requested formats', f"Available formats:\n{extracted_formats}")
        for n, item in enumerate(video_content_info['requested_formats']):
            logger.debug(f"Appending media with format id {item['format_id']}")
            index = [ 'video', 'audio' ]
            req_headers = item.get('http_headers')
            if item.get('cookies'):
                not_cookie_name_words = [ 'domain', 'expires', 'httponly', 'secure', 'path' ]
                cookie_members = []
                for member in item['cookies'].split('; '):
                    if not member.split('=')[0].lower() in not_cookie_name_words:
                        cookie_members.append(member)
                cookie_header = '; '.join(cookie_members)
                req_headers['cookie'] = cookie_header
            stream_url = localize_url(item['url'], req_headers)
            media[index[n]] = { 'url': stream_url }
            mediaflow_url = generate_mediaflow_url(item['url'], headers=req_headers)
            media[index[n]].update({'mediaflow_url': mediaflow_url })
            if 'bilibili' in video_domain:
                media[index[n]].update({ 'segment_base': item.get('segment_base')})
            if item['vcodec'] != 'none':
                has_res = item.get('resolution')
                if has_res:
                    res_member = [ 'width', 'height']
                    for num, value in enumerate(item['resolution'].split('x')):
                        media[index[n]].update({ res_member[num]: value })
                media[index[n]].update({ 'short_url': f'/video?{short_url_qs}' })
                media[index[n]].update({ 'type': f"video/{item['video_ext']}" })
                media[index[n]].update({ 'bitrate': item['vbr'] })
                media[index[n]].update({ 'codecs': item['vcodec'] })
                media[index[n]].update({ 'fps': item.get('fps') })
            else:
                media[index[n]].update({ 'short_url': f'/audio?{short_url_qs}' })
                media[index[n]].update({ 'type': f"audio/{item['audio_ext'].replace('m4a', 'mp4')}" })
                audio_bitrate = item.get('abr') or item.get('tbr')
                if audio_bitrate:
                    if not isinstance(audio_bitrate, float):
                        audio_bitrate = float(audio_bitrate)
                else:
                    audio_bitrate = 0
                media[index[n]].update({ 'bitrate': audio_bitrate })
                media[index[n]].update({ 'codecs': item.get('acodec', 'unknown') })
            if 'm3u8' in item['protocol']:
                media[index[n]].update({ 'type': 'vnd.apple.mpegurl' })
        if video_content_info.get('thumbnail'):
            thumbnail = localize_url(video_content_info['thumbnail'])
        else:
            thumbnail = url_for('static', filename='owl.webp')

        if show_subtitle:
            subtitles = video_content_info.get('subtitles')
        else:
            subtitles = None

        is_youtube = video_domain in [ 'youtube.com', 'youtu.be' ]
        if subtitles and is_youtube:
            media['subtitles'] = {}
            if use_innertube_subtitle:
                # Get subtitle via get_caption api
                lang = sub_lang
                media['subtitles'][lang] = f'/subtitle?{short_url_qs}&lang={lang}'
            else:
                # Rate-limited, expext 429 response after several attempts
                yt_dlp_clients = INNERTUBE_CLIENTS
                logger.debug(f'Subtitle found for {video_id}')
                for lang in list(subtitles.keys()):
                    for sub in subtitles[lang]:
                        if sub['ext'] == 'vtt':
                            ytdl_client = sub.get('__yt_dlp_client')
                            if ytdl_client:
                                subtitle_headers = dict(req_headers)
                                client_ua = yt_dlp_clients[ytdl_client]['INNERTUBE_CONTEXT']['client'].get('userAgent')
                                subtitle_headers['User-Agent'] = client_ua
                            else:
                                subtitle_headers = req_headers
                            media['subtitles'][lang] = get_stream_url(sub['url'], headers=subtitle_headers)
                            logger.debug(f'Extracting {lang} subtitle for {video_id}')
        else:
            media['subtitles'] = None

        media['duration'] = video_content_info.get('duration')
        media['duration_string'] = video_content_info.get('duration_string')
        media['video_id'] = video_id
        media['title'] = video_content_info.get('title', 'Untitled')
        media['description'] = video_content_info.get('description', 'No description provided.')
        media['thumbnail'] = thumbnail
        if media['audio']['type'] == 'vnd.apple.mpegurl' and media['video']['type'] == 'vnd.apple.mpegurl':
            media['is_hls'] = True
        else:
            media['is_hls'] = False
        if video_domain in [ 'youtube.com', 'youtu.be' ] and not media['is_hls']:
            logger.debug(f'Generating segment_base indexRange and initializationRange for {video_id}')
            for index, mtype in enumerate(['video', 'audio']):
                stream_data = video_content_info['requested_formats']
                this_req_headers = stream_data[index].get('http_headers')
                if not this_req_headers:
                    this_req_headers = desktop_headers
                logger.debug(f'Getting 32 kbytes test_segment to be analyzed for {mtype} of {video_id}')
                init_segment = await get_test_segment(stream_data[index]['url'], this_req_headers)
                logger.debug(f'Analyzing test_segment for {mtype} of {video_id}')
                initialization, index_range = find_sidx_moof_mp4(init_segment)
                logger.debug(f'Got segment_base info for {mtype}: {initialization}, {index_range}')
                segment_base_data = { 'initialization': initialization, 'index_range': index_range }
                media[mtype]['segment_base'] = segment_base_data



        if media['is_hls']:
            media['hls_manifest'] = f'/hls/{media_hash}.m3u8'
        elif use_dash_js:
            media['mpd_manifest'] = f'/dash/{media_hash}.mpd'
        media_storage = { media_hash: media }
        if request.args.get('debug'):
            logger.info('Saving video_content_info')
            with open(f'data/video_content_info_{media_hash}.json', 'w') as file:
                json.dump(video_content_info, file)
        logger.debug(f'Appending {media_hash} to media storage')
        await media_json_storage.update(media_storage)
        logger.info(f'Media storage has been updated with {media_hash}')
        logger.debug(f'Original video url: {video_id}')
    mpd_manifest = f"/dash/{media_hash}.mpd"

    return await render_template('testvideo.html', video_id=video_id, media=media, use_dash_js=use_dash_js, sub_lang=sub_lang)

@app.route("/hls/<hash_m3u8>")
@app.route("/hls/subtitle/<hash_m3u8>")
async def generate_playlist(hash_m3u8):
    if not hash_m3u8.endswith('.m3u8'):
        return await show_error_page('Bad request', 'Invalid url for hls manifest', 'Unknown extension for hls manifest.'), 400
    media_hash = os.path.basename(request.path).split('.')[0]
    logger.debug(f'Got media hash: {media_hash}')
    media_data = {}
    try:
        media_data_list = await media_json_storage.read()
        if media_data_list.get(media_hash):
            media_data = media_data_list[media_hash]
        else:
            logger.error(f'Unable to find media data for {media_hash}')
            return await show_error_page('Not found', 'Requested data is not available', f'Unable to find media data for {media_hash}'), 404
            
    except Exception as err:
        logger.error('Media data not found')
        logger.debug(f'Traceback:\n{err}')
        return await show_error_page('Media data not found', 'Unable to access media storage', 'Media storage is not found or inaccessible. Try accessing a video to populate media storage'), 404
    media = media_data
    playlist_content = [
        "#EXTM3U",
        "#EXT-X-INDEPENDENT-SEGMENTS",
        f"#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"audio\",NAME=\"Audio\",URI=\"{ media['audio']['short_url'] }\",DEFAULT=YES",
        f"#EXT-X-STREAM-INF:BANDWIDTH={ int(media['video']['bitrate'] * 1000) },CODECS=\"{ media['video']['codecs'] }\",AUDIO=\"audio\"",
        media['video']['short_url']
    ]
    subtitle_playlist_content = []
    if show_subtitle:
        subtitles = media_data.get('subtitles')
        if subtitles:
            subtitle_line = f'#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="sub1",CHARACTERISTICS="public.accessibility.transcribes-spoken-dialog",NAME="English",AUTOSELECT=YES,DEFAULT=NO,FORCED=NO,LANGUAGE="en-US",URI="/hls/subtitle/{ media_hash }.m3u8"'
            playlist_content.append(subtitle_line)
            for lang in list(subtitles.keys()):
                if sub_lang in lang.lower():
                    subtitle_url = subtitles[lang]
                    logger.debug(f'Subtitle found for {lang} : {subtitle_url}')
                    break
            subtitle_playlist_content = [ '#EXTM3U',
                f"#EXT-X-TARGETDURATION:{ media.get('duration') }",
                '#EXT-X-MEDIA-SEQUENCE:1',
                '#EXT-X-PLAYLIST-TYPE:VOD',
                f"#EXTINF:{ media.get('duration') }",
                subtitle_url,
                '#EXT-X-ENDLIST' ]

    subtitle_requested = request.path.startswith('/hls/subtitle')
    if not subtitle_requested:
        playlist_string = "\n".join(playlist_content)
    else:
        if show_subtitle and subtitle_playlist_content:
            playlist_string = "\n".join(subtitle_playlist_content)
        else:
            playlist_string = ''
    
    return Response(playlist_string, headers={'Content-Type': 'application/vnd.apple.mpegurl'})

@app.route("/dash/<video_hash_mpd>")
async def serve_mpd_manifest(video_hash_mpd):
    if not video_hash_mpd.endswith('.mpd'):
        return await show_error_page('Bad Request', 'Invalid url for mpd manifest', 'Unknown extension for dash manifest'), 400
    video_hash = video_hash_mpd.split('.')[0]
    media = await media_json_storage.read()
    media_selected = media.get(video_hash)
    if media_selected:
        return await render_template('manifest.mpd', media=media_selected, get_period_mpd=get_period_mpd), 200, {'Content-Type': 'application/dash+xml'}
    else:
        return await show_error_page('No Data', 'Unable to find requested data', 'The requested media_hash is not in media storage. Make sure to refresh the view_page after cleaning up to get updated media_hash data'), 404

@app.route("/video")
@app.route("/audio")
async def redirect_to_full_path():
    media_hash = request.args.get('hash')
    if not media_hash:
        await show_error_page('No hash provided', 'Unable to find hash query string', 'Make sure to include a valid media hash as <code>hash</code> query string'), 400
    if 'video' in request.path:
        current_item = 'video'
    elif 'audio' in request.path:
        current_item = 'audio'
    try:
        media_data_list = await media_json_storage.read()
        if media_data_list.get(media_hash):
            media = media_data_list.get(media_hash)
            if use_mediaflow:
                full_url = media[current_item]['mediaflow_url']
                if full_url is None:
                    full_url = media[current_item]['url']
            else:
                full_url = media[current_item]['url']

            location_header = { 'Content-Type': '', 'Location': full_url }
            return Response('', 302, headers=location_header)
        else:
            await show_error_page('Hash not found', 'Could not get the requested hash media info', 'Unable to look up hash in media storage. Try refreshing view page after cleaning up.'), 404
    except Exception as err:
        logger.error(f'Got an unexpected error getting full_url of {media_hash}')
        logger.debug(f'Traceback:\n{err}')
        return await show_error_page('Unknown error', 'Go an unexpected error', f'Traceback:\n{err}'), 404

@app.route("/stream", methods=[ 'GET', 'HEAD' ])
@app.route("/stream/<path:url_part>", methods=[ 'GET', 'HEAD' ])
async def stream(url_part: str = ''):
    qs_dict = dict(request.args)
    referer = qs_dict.get('referer')
    if referer:
        unquoted_referer = urllib.parse.unquote(referer)
        parsed_referer = urllib.parse.urlparse(unquoted_referer)
        fixed_referer = f'{parsed_referer.scheme}://{parsed_referer.hostname}'
        qs_dict.pop('referer')
    headers_base64 = qs_dict.get('headers')
    req_headers = {}
    if headers_base64:
        decoded_headers = base64.urlsafe_b64decode(headers_base64).decode('utf-8')
        req_headers = json.loads(decoded_headers)
        logger.debug(f"req_headers is {req_headers}")
        qs_dict.pop('headers')
    qs = urllib.parse.urlencode(qs_dict)
    if url_part:
        parsed_url_part = urllib.parse.urlparse(url_part)
        url_part_path = parsed_url_part.path
        hls_url = url_part_path.startswith('hls')
        localized_url = not hls_url
        if localized_url and qs_dict:
            logger.debug("Getting original url via url_part (with qs)")
            base64_url = url_part.split('?')[0]
            video_url_quoted = base64.urlsafe_b64decode(base64_url.encode()).decode('utf-8')
            video_url_untested = urllib.parse.unquote(video_url_quoted)
            video_url = normalize_url(video_url_untested)
            logger.debug(f"Got video url: {video_url}")
        if localized_url and not qs_dict:
            logger.debug("Getting original url via url_part")
            base64_url = url_part
            video_url_quoted = base64.urlsafe_b64decode(base64_url.encode()).decode('utf-8')
            video_url_untested = urllib.parse.unquote(video_url_quoted)
            video_url = normalize_url(video_url_untested)
            logger.debug(f"Got video url: {video_url}")
        if hls_url:
            video_url, req_headers = decode_proxified_url(request.url)
            logger.debug(f'Got original hls stream manifest: {video_url}')
    else:
        logger.debug('Got original url from query_string')
        media_url_base64 = request.args.get('media_url')
        media_url = base64.urlsafe_b64decode(media_url_base64).decode('utf-8')
        video_url = media_url
        logger.debug(f'{video_url}')
    parsed_video_url = urllib.parse.urlparse(video_url)
    allowed_hosts = [ 'googlevideo.com', 'ytimg.com', 'akamaized.net', 'bilivideo.com', 'bstarstatic.com', 'hdslb.com', 'nicovideo.jp', 'nimg.jp' ]
    if show_subtitle:
        allowed_hosts.append('youtube.com')
    hostname_part = parsed_video_url.hostname.split('.')
    domain = '.'.join([ hostname_part[-2], hostname_part[-1] ])
    if domain not in allowed_hosts:
        logger.error(f'{domain} is not in allowed_hosts')
        return await show_error_page('Forbidden', f'Sorry, {domain} is not in allowed_hosts.', f'Domain {domain} is not in allowed_hosts.'), 403
    if req_headers:
        client_headers = req_headers
    else:
        client_headers = desktop_headers
    yt_request = domain in [ 'googlevideo.com', 'youtube.com' ]
    if yt_request:
        logger.debug(f'yt_request detected: {domain}')
        client_headers['Origin'] = 'https://www.youtube.com'
        client_headers['Referer'] = 'https://www.youtube.com'
    range_header = request.headers.get('Range')
    cookies = cookiejar
    is_hls = parsed_video_url.path.endswith('.m3u8') or parsed_video_url.path.endswith('.m3u')
    is_segment = parsed_video_url.path.endswith('.ts')
    # Do not use cookiejar for hls, to use Cookie header from video_content_info earlier
    if is_hls and is_segment:
        session_client = httpx.AsyncClient(headers=client_headers, follow_redirects=True, http2=True)
    else:
        session_client = httpx.AsyncClient(headers=client_headers, follow_redirects=True, http2=True, cookies=cookies)

    if request.method == 'HEAD':
        status_code, server_headers = await head(video_url, session_client, client_headers)
        return '', status_code, server_headers 

    if range_header:
        client_headers['Range'] = range_header

    video_hosts = [ 'googlevideo.com', 'akamaized.net', 'nicovideo.jp']
    video = domain in video_hosts
    gvs_server = yt_request
    server_headers = {}
    status_code = None

    if video and not is_hls:
        if range_header:
            my_resp = await non_streaming(video_url, session_client, client_headers)
            server_headers.update(appended_headers)
            return my_resp
        elif gvs_server and not range_header:
            my_resp = await make_response(streaming(video_url, session_client, client_headers))
        else:
            my_resp = await make_response(streaming_with_retries(video_url, session_client, client_headers))
        server_headers.update(appended_headers)
        my_resp.headers = server_headers
        my_resp.timeout = None
        return my_resp
    else:
        return await non_streaming(video_url, session_client, client_headers)

@app.route('/bilisearch')
async def bilisearch():
    search_query = request.args.get('query')
    if not search_query:
        return await render_template('search.html')
    page_num_result = request.args.get('pagenum') or 1
    if not isinstance(page_num_result, int):
        page_num_result = int(page_num_result)
    page_next = page_num_result + 1
    homepage = 'https://www.bilibili.com'
    homepage_resp = await async_client.get(homepage)
    homepage_resp.raise_for_status()
    if homepage_resp.cookies:
        cookiejar.save()
    await asyncio.sleep(1)
    await homepage_resp.aclose()
    search_api = 'https://api.bilibili.com/x/web-interface/search/all/v2'
    if page_num_result:
        api_query = urllib.parse.urlencode({'keyword': search_query, 'page': page_num_result })
    else:
        api_query = urllib.parse.urlencode({'keyword': search_query })
    search_resp = await async_client.get(f'{search_api}?{api_query}')
    search_resp.raise_for_status()
    resp_dict = json.loads(search_resp.text)
    if resp_dict.get('data'):
        total_result = resp_dict['data']['numResults']
        total_pages = resp_dict['data']['numPages']
        result_list_category = resp_dict['data']['result']
        for n, category in enumerate(result_list_category):
            if not len(category) == 0:
                if category['result_type'] == 'video':
                    video_data = category
                    result = video_data['data']
                    break
    search_data = []
    for item in result:
        if item.get('pic'):
            scaled_resolution_param = '@672w_378h_1c_!web-search-common-cover.webp'
            if not item['pic'].startswith('http'):
                thumbnail_url = f"https:{item['pic']}{scaled_resolution_param}"
            else:
                thumbnail_url = f"item['pic']{scaled_resolution_param}"
            thumbnail = localize_url(thumbnail_url)
        else:
            thumbnail = url_for('static', filename='owl.webp')
        if item.get('title'):
            title = Markup(item['title']).striptags()
        else:
            title = 'Untitled'

        if item.get('duration'):
            raw_duration = item.get('duration')
            raw_duration_split = raw_duration.split(':')
            formatted_duration = []
            for num in raw_duration_split:
                formatted_num = '{:0>2}'.format(num)
                formatted_duration.append(formatted_num)
            duration = ':'.join(formatted_duration)
        else:
            duration = '00:00'

        constructed_url = f"https://www.bilibili.com/video/{item['bvid']}"
        data = {
                'title': title,
                'author': item.get('author', 'Anonymous'),
                'video_id': item.get('bvid', 'unknown'),
                'play_count': item.get('play', 0),
                'web_url': f"/view_page?v={urllib.parse.quote(constructed_url)}",
                'duration': duration,
                'thumbnail': thumbnail
                }
        search_data.append(data)
    return await render_template('search_result.html', search_data=search_data, search_query=search_query, page_next=page_next, total_result=total_result, total_pages=total_pages)

@app.route("/nicosearch")
async def get_result():
    cookies = cookiejar
    hdr = { 'User-Agent': 'NicoApiClient 0.5.0',
            'Accept-Language': 'en-us,en;q=0.5',
           }
    api_v2 = 'https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search'
    query_string = request.args.get('query')
    if not query_string:
        return await render_template('nico_search.html')
    # Available targets: title, tagsExact
    offset_query = request.args.get('offset', 0)
    if not isinstance(offset_query, int):
        offset_query = int(offset_query)
    result_per_page = request.args.get('max_result', 20)
    if not isinstance(result_per_page, int):
        result_per_page = int(result_per_page)
    query = urllib.parse.urlencode({
        'targets': 'title',
        'q': f'{query_string}',
        'fields': 'contentId,lengthSeconds,title,thumbnailUrl,viewCounter',
        '_sort': '-viewCounter',
        '_offset': offset_query,
        '_limit': result_per_page,})
    resp = await async_client.get(f"{api_v2}?{query}", headers=hdr)
    if resp.status_code >= 400:
        logger.error(f'Got error from nicosearch api:\n{resp.text}')
    resp.raise_for_status()
    result_dict = resp.json()
    if request.args.get('debug'):
        with open('data/nicosearch_debug.json', 'w') as file:
            logger.debug("Saving debug information for nicosearch")
            file.write(resp.text)
    await resp.aclose()
    watch_page = 'https://www.nicovideo.jp/watch'
    result_items = result_dict.get('data')
    metadata = result_dict.get('meta')
    if metadata:
        total_result = metadata.get('totalCount', 'unknown')
    else:
        total_result = 'unknown'
    if not result_items:
        return await show_error_page('Got no search result', 'No more items to show', json.dumps(result_dict, indent=2)), 404
    for item in result_items:
        item['unescaped_title'] = Markup(item['title']).unescape()
        full_url = f"{watch_page}/{item['contentId']}"
        url_data = urllib.parse.urlencode({'v': full_url })
        routed_url = f"/view_page?{url_data}"
        item['url'] = routed_url
        if item.get('lengthSeconds'):
            item['duration'] = get_period_text(item['lengthSeconds'])
        item['thumbnail'] = localize_url(item['thumbnailUrl']+'.M')
    next_page_qs = urllib.parse.urlencode(
            { 'query': query_string,
              'offset': offset_query + result_per_page,
             })
    next_page_url = f'nicosearch?{next_page_qs}'
    return await render_template('nico_search_result.html', result_items=result_items, query=query_string, watch_page=watch_page, next_page_url=next_page_url, total_result=total_result)

@app.route('/ytsearch', methods=['GET', 'POST'])
async def ytsearch():
    search_query_raw = request.args.get('query')
    if not search_query_raw:
        return await render_template('ytsearch.html')
    if request.method == 'GET':
        search_query = urllib.parse.quote_plus(search_query_raw)
    else:
        search_query = search_query_raw
    query = { 'search_query': search_query }
    query_encoded = urllib.parse.urlencode(query)
    youtube = 'https://www.youtube.com'
    search_page = f"{youtube}/results?{query_encoded}"
    query_encoded = urllib.parse.urlencode(query)
    is_next_page = request.method == 'POST'
    if is_next_page:
        form_data = await request.form
        continuation_token = form_data.get('ctoken')
        if not continuation_token:
            return await render_template('ytsearch.html')
    home_resp = await async_client.get(youtube)
    if not os.path.isdir('data'):
        os.makedirs('data')
    if home_resp.cookies:
        logger.info(f"Saving updated cookies from {youtube}")
        cookiejar.save()
    await asyncio.sleep(1)
    await home_resp.aclose()
    ytcfg = await get_ytcfg()
    yt_search_api = f"{youtube}/youtubei/v1/search?{ytcfg['INNERTUBE_API_KEY']}"
    debug = request.args.get('debug')
    async def get_result():
        max_retries = 3
        retry = 0
        while retry <= max_retries:
            referer_hdr = { 'Referer': youtube }
            if not is_next_page:
                search_payload = { 'context': ytcfg['INNERTUBE_CONTEXT'],
                                   'query': search_query }
                resp = await async_client.post(yt_search_api, headers=referer_hdr, json=search_payload)
                if resp.cookies:
                    logger.info(f"Saving updated cookies from {youtube} (next page)")
                    cookiejar.save()
                try:
                    resp.raise_for_status()
                except Exception as err:
                    logger.error(f'Got non 200 status from YT\n{err}')
                    await asyncio.sleep(1)
                    await resp.aclose()
                    return Response("<p>Got non 200 status code from YT</p>")
                initial_data_json = await resp.aread()
                await resp.aclose()
                initial_data = json.loads(initial_data_json.decode())
                if debug:
                    with open(os.path.join('data','search_debug.json'), 'w') as file:
                        logger.debug('Writing search response initialData to file')
                        json.dump(initial_data, file, indent=2)
                if initial_data.get('estimatedResults'):
                    logger.debug(f"About {initial_data['estimatedResults']}")
                    contents = initial_data['contents']['twoColumnSearchResultsRenderer']['primaryContents']['sectionListRenderer']['contents'][0]['itemSectionRenderer']['contents']
                    if not contents:
                        logger.warning('Unable to get search content, retrying')
                        retry +=1
                        await asyncio.sleep(3)
                    else:
                        search_data = []
                        for member in contents:
                            key = list(member.keys())[0]
                            if not member.get(key):
                                loging.debug(member.keys())
                                pass
                            else:
                                item = member[key]
                                if item.get('videoId'):
                                    logger.debug(f"Appending {item['videoId']} to the search result")
                                    data = {}
                                    data['video_id'] = item['videoId']
                                    video_url = f"{youtube}/watch?v={item['videoId']}"
                                    quoted_video_url = urllib.parse.quote(video_url)
                                    video_url_proxied = f'/view_page?v={quoted_video_url}'
                                    data['url'] = video_url_proxied
                                    data['title'] = item['title']['runs'][0]['text']
                                    thumbnail_url = item['thumbnail']['thumbnails'][-1]['url']
                                    data['thumbnail'] = localize_url(thumbnail_url)
                                    if item.get('lengthText'):
                                        data['length'] = item['lengthText'].get('simpleText', 'unknown')
                                    else:
                                        data['length'] = '0:00'
                                    if item.get('viewCountText'):
                                        data['view_count'] = item['viewCountText'].get('simpleText', 'unknown')
                                    else:
                                        data['view_count'] = 'unknown'
                                    search_data.append(data)
                        search_result = {}
                        search_result['query'] = search_query_raw
                        next_data_dict = {'query': search_query, 'next': True}
                        if debug:
                            next_data_dict['debug'] = debug
                        next_data = urllib.parse.urlencode(next_data_dict)
                        search_result['next_page_url'] = f"ytsearch?{next_data}"
                        search_result['estimatedResults'] = initial_data['estimatedResults']
                        search_result['contents'] = search_data
                        continuationCommand = find_by_key(initial_data, 'continuationCommand')
                        if continuationCommand:
                            search_result['ctoken'] = continuationCommand.get('token')
                        return await render_template('ytsearch_result.html', search_result=search_result)
                else:
                    logger.warning('Unable to know estimatedResults, retrying.')
                    retry += 1
                    await asyncio.sleep(3)
            else:
                # This is to get continuation page.
                ctoken = form_data.get('ctoken')
                payload = { 'context': ytcfg['INNERTUBE_CONTEXT'] , 'continuation': ctoken }
                resp = await async_client.post(yt_search_api, json=payload, headers=referer_hdr)
                try:
                    resp.raise_for_status()
                except Exception as err:
                    logger.error(f'Got non 200 response from YT\n{err}')
                    response_payload = { 'status': 'ERROR',
                                        'message': 'Got non 200 status from YT api' }
                    return Response(json.dumps(response_payload, indent=2), content_type="application/json")
                next_page_data = resp.json()
                if request.args.get('debug'):
                    with open(os.path.join('data','next_debug.json'), 'w') as file:
                        logger.debug('Dumping search next page json')
                        json.dump(next_page_data, file)

                next_contents = next_page_data['onResponseReceivedCommands'][0]['appendContinuationItemsAction']['continuationItems']
                if next_contents:
                    logger.debug(next_contents[0].keys())
                    next_contents_items = next_contents[0]['itemSectionRenderer']['contents']

                    if not next_contents_items:
                        logger.error('No item for next contents')
                        return Response(json.dumps({'status': 'ERROR', 'message': 'No item for next content'}), content_type="application/json")

                    search_data = []
                    for member in next_contents_items:
                        logger.debug(member.keys())
                        if not member.get('videoRenderer'):
                            pass
                        else:
                            item = member['videoRenderer']
                            logger.debug(item.keys())
                            if item.get('videoId'):
                                logger.debug(f"Appending {item['videoId']} to the search result")
                                data = {}
                                data['video_id'] = item['videoId']
                                video_url = f"{youtube}/watch?v={item['videoId']}"
                                quoted_video_url = urllib.parse.quote(video_url)
                                video_url_proxied = f'/view_page?v={quoted_video_url}'
                                data['url'] = video_url_proxied
                                data['title'] = item['title']['runs'][0]['text']
                                thumbnail_url = item['thumbnail']['thumbnails'][-1]['url']
                                thumbnail_b64 = base64.urlsafe_b64encode(thumbnail_url.encode('utf-8'))
                                thumbnail_data = urllib.parse.urlencode({'media_url': thumbnail_b64 })
                                data['thumbnail'] = f'/stream?{thumbnail_data}'
                                data['length'] = item['lengthText']['simpleText']
                                if item.get('viewCountText'):
                                    data['view_count'] = item['viewCountText']['simpleText']
                                else:
                                    data['view_count'] = 'unknown views'
                                search_data.append(data)
                    search_result = {}
                    search_result['query'] = search_query_raw
                    next_data_dict = {'query': search_query, 'next': True}
                    if debug:
                        next_data_dict['debug'] = debug
                    next_data = urllib.parse.urlencode(next_data_dict)
                    search_result['next_page_url'] = f"ytsearch?{next_data}"
                    search_result['estimatedResults'] = next_page_data['estimatedResults']
                    search_result['contents'] = search_data
                    continuationCommand = find_by_key(next_page_data, 'continuationCommand')
                    if continuationCommand:
                        search_result['ctoken'] = continuationCommand.get('token')
                    return await render_template('ytsearch_result.html', search_result=search_result)

            if retry >= max_retries:
                logger.error('Max retries exceeded')
                return Response(json.dumps({'status': 'ERROR',
                        'message': 'Got no result from YT after {max_retries} attempts.'}),
                        404, content_type="application/json")


    return await get_result()

@app.route('/health_check')
async def health_check():
    is_debug = request.args.get('debug')
    url = 'https://cloudflare.com/cdn-cgi/trace'
    try:
        resp = await async_client.get(url)
    except Exception as err:
        logger.error(f'Got an exception during health check\nTraceback:\n{err}')
        return 'Unhealthy', 500, { 'Content-Type': 'text/plain' }
    finally:
        await resp.aclose()
    if resp.status_code == 200:
        logger.info('Health check OK')
        if is_debug:
            healthcheck_result = resp.content
            return Response(healthcheck_result, 200, headers={ 'Content-Type': 'text/plain' })
        else:
            return 'OK', 200, { 'Content-Type': 'text/plain' }
    else:
        logger.error('Health check failed')
        return 'Unhealthy', 500, { 'Content-Type': 'text/plain' }


@app.route('/clean_up', methods=['GET', 'POST'])
async def clean_up():
    if request.method == 'GET':
        return '', 302, { 'Location': 'settings' }
    form_data = await request.form
    is_okay = escape(form_data.get('confirmation'))
    include_session_key = form_data.get('include_session_key')
    items_to_clean = [ 'media_storage.json', 'cookies.txt', 'ytcfg.json' ]
    if include_session_key:
        items_to_clean.append('session_key.txt')
    if is_okay:
        for item in items_to_clean:
            file_path = os.path.join('data', item)
            if os.path.isfile(file_path):
                logger.info(f'Cleaning up {item}')
                os.remove(file_path)
                logger.info('Done')
                await flash(f'The media storage for {item} has been cleaned up')
            else:
                logger.warning('Nothing to clean up')
                await flash(f'Nothing to do for {item}')
        return '', 302, { 'Location': 'settings' }

@app.route('/favicon.ico')
def favicon():
    return Response(None, 204)

@app.route('/settings', methods=['GET', 'POST'])
async def settings():
    settings_file = 'data/settings.ini'
    cfg = configparser.ConfigParser()
    
    # Validation constants
    VALID_HEIGHTS = [144, 240, 360, 480, 720, 1080]
    VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

    try:
        with open(settings_file, 'r') as file:
            settings_value = cfg.read_file(file)
    except Exception as err:
        logger.warning('No settings available, using default value')
        cfg.read_dict(*default_value)

        if not os.path.isdir('data'):
            os.makedirs('data')

        with open(settings_file, 'w') as file:
            cfg.write(file)
            logger.info(f'Configuration saved to {settings_file}')

    if request.method == 'GET':
        return await render_template('settings.html', cfg=cfg), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        }
    
    elif request.method == 'POST':
        cfg_form = await request.form
        validation_errors = []

        # Validate video height
        try:
            video_height = int(cfg_form.get('video_height', 360))
            if video_height not in VALID_HEIGHTS:
                validation_errors.append(f"Invalid video height. Choose from {VALID_HEIGHTS}")
                video_height = 360  # Default fallback
        except ValueError:
            validation_errors.append("Video height must be an integer")
            video_height = 360

        # Validate log level
        log_level = cfg_form.get('log_level', 'INFO').upper()
        if log_level not in VALID_LOG_LEVELS:
            validation_errors.append(f"Invalid log level. Choose from {VALID_LOG_LEVELS}")
            log_level = 'INFO'

        # Validate boolean flags
        boolean_flags = [
            'use_mediaflow', 
            'use_dash_js', 
            'show_subtitle', 
            'use_innertube_subtitle'
        ]
        
        for section in cfg.sections():
            for key in cfg[section].keys():
                # Sanitize input
                value = escape(cfg_form.get(key, ''))
                
                # Special handling for boolean flags
                if key in boolean_flags:
                    value = 'True' if value.lower() in ['on', 'true', '1'] else 'False'
                
                # Special handling for specific keys
                if key == 'video_height':
                    value = str(video_height)
                elif key == 'log_level':
                    value = log_level
                
                logger.debug(f"Updating value for {key}: {value}")
                cfg[section][key] = value

        # Write updated configuration
        with open(settings_file, 'w') as file:
            logger.info('Saving updated configuration')
            cfg.write(file)

        # Flash validation errors or success message
        if validation_errors:
            for error in validation_errors:
                await flash(error, 'error')
        else:
            await flash('Configuration has been updated', 'success')

        return await render_template('settings.html', cfg=cfg), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        }

@app.route('/subtitle')
async def get_vtt_from_video_id():
    try:
        media_data = await media_json_storage.read()
    except Exception as err:
        logger.error('No media data is present')
        return await show_error_page('No media data', 'No media data is present', 'Try loading a watch page to populate media data'), 404
    media_hash = request.args.get('hash')
    if media_hash:
        video_id = media_data[media_hash].get('video_id')
    parsed_video_url = urllib.parse.urlparse(video_id)
    is_youtube = '.'.join(parsed_video_url.hostname.split('.')[-2:]) in ['youtube.com', 'youtu.be']
    if not is_youtube:
        err_message = 'Non youtube url is not supported'
        logger.error(err_message)
        return await show_error_page('Not supported', err_message, 'Only youtube is available via this route'), 400
    qs = urllib.parse.parse_qs(parsed_video_url.query)
    if qs.get('v') and parsed_video_url.hostname.endswith('youtube.com'):
        yt_video_id = qs['v'][0]
    elif parsed_video_url.hostname.endswith('youtu.be'):
        yt_video_id = os.path.basename(parsed_video_url.path)
    if qs.get('lang'):
        lang = qs['lang'][0]
    else:
        lang = sub_lang
    params = generate_caption_params(yt_video_id, lang)
    json_resp = await post_subtitle_request(params)
    caption_data = await extract_caption_segments_from_json(json.loads(json_resp.decode()))
    continuation = test_continuation(caption_data)
    if continuation:
        logger.warning('Got continuation response, retrying')
        new_json_resp = await post_subtitle_request(continuation)
        new_caption_data = await extract_caption_segments_from_json(json.loads(new_json_resp.decode()))
        continuation_new = test_continuation(new_caption_data)
        if continuation_new:
            logger.error(f'Got another continuation: {continuation_new}')
            return ''
        else:
            logger.debug('Got vtt after continuation retry')
            webvtt_raw = await webvtt_from_caption_data(new_caption_data)
    else:
        webvtt_raw = await webvtt_from_caption_data(caption_data)
    webvtt = Markup(webvtt_raw).unescape()
    return webvtt, 200, {'Content-Type': 'text/vtt' }

@app.route('/proxy/<path:path>')
async def proxy(path):
    if not use_mediaflow:
        return abort(403)
    assert mediaflow_instance.startswith('http')
    url = f'{mediaflow_instance}/proxy/{path}'
    if request.query_string:
        url += f'?{request.query_string.decode()}'
    allowed_hosts = [ 'googlevideo.com', 'ytimg.com', 'akamaized.net', 'bilivideo.com', 'bstarstatic.com', 'hdslb.com', 'nicovideo.jp', 'nimg.jp' ]
    destination_url = request.args.get('d')
    if destination_url:
        hostname = urllib.parse.urlparse(urllib.parse.unquote(destination_url)).hostname
        hostname_splitted = hostname.split('.')
        domain = '.'.join(hostname_splitted[-2:])
        if not domain in allowed_hosts:
            error = { 'status': 'FORBIDDEN',
                     'message': f"{hostname} is not in allowed hosts" }
            return json.dumps(error, indent=2) , 403, { 'Content-Type': 'application/json' }

    async with httpx.AsyncClient() as client:
        response = await client.request(
            request.method,
            url,
            headers=request.headers
        )

    return Response(
        response.content,
        status=response.status_code,
        headers=dict(response.headers)
    )
