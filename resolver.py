#!/usr/bin/env python3
"""
Local traffic-flow analyzer and resolver test API.

This is intended for authorized debugging of captures in this folder. It
detects protected flows honestly and does not attempt CAPTCHA, DRM, login, or
anti-bot bypasses.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_TEST_URL = "https://www.2embed.stream/embed/movie/tt0373074"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)
MEDIA_RE = re.compile(r"https?://[^\s\"'<>\\]+?(?:\.m3u8|\.mpd|\.mp4|/video\.m3u8)(?:[^\s\"'<>\\]*)?", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
PROTECTION_RE = re.compile(
    r"captcha|turnstile|cf-chl|challenge-platform|cf_clearance|widevine|playready|fairplay|drm|license",
    re.I,
)
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "token",
    "hash",
    "q",
    "id1",
    "sig",
    "signature",
    "expires",
    "key",
}


def now_ms() -> int:
    return int(time.time() * 1000)


def add_unique(items: List[Any], item: Any) -> None:
    if item not in items:
        items.append(item)


def short_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def base_n_to_int(value: str, base: int) -> int:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = 0
    for char in value:
        digit = alphabet.find(char)
        if digit < 0 or digit >= base:
            raise ValueError(f"invalid base-{base} digit: {char}")
        result = result * base + digit
    return result


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted = []
    for key, value in pairs:
        if key.lower() in SENSITIVE_KEYS or len(value) > 48:
            value = f"<redacted:{len(value)}>"
        redacted.append((key, value))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(redacted), parsed.fragment)
    )


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        if value.startswith("http://") or value.startswith("https://"):
            return redact_url(value)
        if len(value) > 80:
            return f"<redacted:{len(value)}>"
        return value
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                out[key] = f"<redacted:{len(str(item))}>"
            else:
                out[key] = redact_value(item)
        return out
    return value


def safe_json(data: Any, redact: bool) -> str:
    if redact:
        data = redact_value(data)
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)


@dataclass
class Step:
    action: str
    url: Optional[str] = None
    status: Optional[int] = None
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


@dataclass
class ResolveResult:
    original_url: str
    status: str = "started"
    resolved_url: Optional[str] = None
    ids: Dict[str, Any] = field(default_factory=dict)
    tokens: Dict[str, Any] = field(default_factory=dict)
    source_servers: List[Dict[str, Any]] = field(default_factory=list)
    iframe_urls: List[str] = field(default_factory=list)
    embed_urls: List[str] = field(default_factory=list)
    media_urls: List[str] = field(default_factory=list)
    resource_urls: List[str] = field(default_factory=list)
    protection_findings: List[str] = field(default_factory=list)
    request_steps: List[Step] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    blocked: bool = False

    def step(self, action: str, url: Optional[str] = None, status: Optional[int] = None, note: str = "") -> None:
        self.request_steps.append(Step(action, url, status, note))

    def as_dict(self) -> Dict[str, Any]:
        data = dict(self.__dict__)
        data["request_steps"] = [s.as_dict() for s in self.request_steps]
        return data


class Fetcher:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.cookiejar: Dict[str, str] = {}

    def headers(self, referer: Optional[str] = None, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if referer:
            headers["Referer"] = referer
            origin = urllib.parse.urlsplit(referer)
            headers["Origin"] = f"{origin.scheme}://{origin.netloc}"
        if self.cookiejar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookiejar.items())
        if extra:
            headers.update(extra)
        return headers

    def store_cookies(self, response: urllib.response.addinfourl) -> None:
        for raw in response.headers.get_all("Set-Cookie", []):
            pair = raw.split(";", 1)[0]
            if "=" in pair:
                name, value = pair.split("=", 1)
                if name and value:
                    self.cookiejar[name] = value

    def request(
        self,
        url: str,
        method: str = "GET",
        referer: Optional[str] = None,
        data: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str, Dict[str, str]]:
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers=self.headers(referer, extra_headers),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.store_cookies(resp)
                body = resp.read()
                charset = resp.headers.get_content_charset() or "utf-8"
                text = body.decode(charset, errors="replace")
                return resp.status, resp.geturl(), text, dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, exc.geturl(), body, dict(exc.headers.items())


def normalize_url(url: str, base: str) -> str:
    url = html.unescape(url.strip())
    if url.startswith("//"):
        scheme = urllib.parse.urlsplit(base).scheme or "https"
        return f"{scheme}:{url}"
    return urllib.parse.urljoin(base, url)


def extract_urls(text: str, base: str = "") -> List[str]:
    found: List[str] = []
    for match in URL_RE.findall(text or ""):
        add_unique(found, html.unescape(match).rstrip(".,;"))
    for attr in re.findall(r"""(?:src|href|data-src|poster)\s*=\s*["']([^"']+)["']""", text or "", re.I):
        add_unique(found, normalize_url(attr, base))
    return found


def extract_media_urls(text: str, base: str = "") -> List[str]:
    found: List[str] = []
    for match in MEDIA_RE.findall(text or ""):
        add_unique(found, html.unescape(match).rstrip(".,;"))
    for rel in re.findall(r"""["']([^"']+\.(?:m3u8|mpd|mp4)(?:\?[^"']*)?)["']""", text or "", re.I):
        add_unique(found, normalize_url(rel, base))
    return found


def extract_iframes(text: str, base: str) -> List[str]:
    found: List[str] = []
    for match in re.findall(r"""<iframe\b[^>]*(?:src|data-src)\s*=\s*["']([^"']+)["']""", text or "", re.I):
        add_unique(found, normalize_url(match, base))
    return found


def extract_2embed_ids(url: str, text: str = "") -> Dict[str, Any]:
    ids: Dict[str, Any] = {}
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path
    query = urllib.parse.parse_qs(parsed.query)
    imdb = re.search(r"/(?:embed/)?(?:movie|tv)/(?P<id>tt\d+)", path)
    if imdb:
        ids["imdb_id"] = imdb.group("id")
        ids["kind"] = "movie" if "/movie/" in path else "tv"
    if "id" in query:
        ids["id"] = query["id"][0]
        if re.match(r"tt\d+", ids["id"]):
            ids["imdb_id"] = ids["id"]
    vidcore = re.search(r"/(?:movie|tv)/(?P<id>\d+)", path)
    if "vidcore.net" in parsed.netloc and vidcore:
        ids["vidcore_id"] = vidcore.group("id")
    for key in ("imdb_id", "vidcore_id"):
        if key not in ids:
            pattern = r"(tt\d{5,}|\b\d{6,}\b)"
            for m in re.findall(pattern, text):
                if m.startswith("tt"):
                    ids["imdb_id"] = m
                elif "vidcore" in text[:5000].lower():
                    ids["vidcore_id"] = m
    return ids


def unpack_dean_edwards(source: str) -> List[str]:
    scripts: List[str] = []
    pattern = re.compile(
        r"eval\(function\(p,a,c,k,e,d\).*?\(\s*'(?P<p>(?:\\.|[^'])*)'\s*,\s*(?P<a>\d+)\s*,\s*(?P<c>\d+)\s*,\s*'(?P<k>(?:\\.|[^'])*)'\.split\('\|'\)",
        re.S,
    )
    for match in pattern.finditer(source or ""):
        try:
            payload = bytes(match.group("p"), "utf-8").decode("unicode_escape")
            radix = int(match.group("a"))
            count = int(match.group("c"))
            words = bytes(match.group("k"), "utf-8").decode("unicode_escape").split("|")
            if len(words) < count:
                words.extend([""] * (count - len(words)))

            def replace_token(token_match: re.Match[str]) -> str:
                token = token_match.group(0)
                try:
                    index = base_n_to_int(token, radix)
                except ValueError:
                    return token
                if 0 <= index < len(words) and words[index]:
                    return words[index]
                return token

            scripts.append(re.sub(r"\b\w+\b", replace_token, payload))
        except Exception:
            continue
    return scripts


def extract_double_base64_scripts(text: str) -> List[str]:
    decoded: List[str] = []
    for raw in re.findall(r"""<script[^>]+type=["']text/plain["'][^>]*>([A-Za-z0-9+/=\s]+)</script>""", text or "", re.I):
        blob = "".join(raw.split())
        for _ in range(2):
            try:
                blob = base64.b64decode(blob).decode("utf-8", errors="replace")
            except Exception:
                break
        if blob and len(blob) > 20:
            decoded.append(blob)
    return decoded


def parse_xfilesharing_page(url: str, text: str) -> Dict[str, Any]:
    joined_scripts = [text] + unpack_dean_edwards(text) + extract_double_base64_scripts(text)
    joined = "\n".join(joined_scripts)
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc
    file_code = None
    for regex in [
        r"file_code['\"]?\s*[:=]\s*['\"]([^'\"]+)",
        r"/(?:embed|e)/([A-Za-z0-9_-]+)",
        r"tt([A-Za-z0-9_-]{6,})",
    ]:
        match = re.search(regex, joined + "\n" + url)
        if match:
            file_code = match.group(1)
            break

    details: Dict[str, Any] = {
        "host": host,
        "file_code": file_code,
        "media_urls": extract_media_urls(joined, url),
        "urls": extract_urls(joined, url),
        "dl_urls": [],
        "unpacked_scripts": len(joined_scripts) - 1,
    }

    for rel in re.findall(r"""["'](/dl\?[^"']+)["']""", joined, re.I):
        absolute = normalize_url(rel, url)
        if re.search(r"(?:\?|&)op=|(?:\?|&)file_code=", absolute):
            add_unique(details["dl_urls"], absolute)
    for full in re.findall(r"""https?://[^"']+/dl\?[^"']+""", joined, re.I):
        if re.search(r"(?:\?|&)op=|(?:\?|&)file_code=", full):
            add_unique(details["dl_urls"], full)

    hash_value = None
    hash_match = re.search(r"(?:hash|file_real)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_.:-]{20,})", joined)
    if hash_match:
        hash_value = hash_match.group(1)
        details["hash"] = hash_value

    referer = None
    ref_match = re.search(r"(?:referer|ref_url)['\"]?\s*[:=]\s*['\"]([^'\"]+)", joined)
    if ref_match:
        referer = ref_match.group(1)
        details["referer"] = referer

    if file_code and hash_value:
        params = {
            "op": "view",
            "file_code": file_code,
            "hash": hash_value,
            "embed": "1",
            "referer": referer or urllib.parse.urlsplit(url).netloc,
            "adb": "1",
            "hls4": "1",
        }
        dl = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/dl", urllib.parse.urlencode(params), ""))
        add_unique(details["dl_urls"], dl)

    return details


def parse_vidcore_page(url: str, text: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "host": "vidcore.net",
        "media_urls": extract_media_urls(text, url),
        "resource_urls": [],
    }
    for match in re.findall(r'\{\\"en\\":\\"([^"]+)\\".*?\\"id\\":\\"([^"]+)\\"', text):
        info["en_token"] = match[0]
        info["vidcore_id"] = match[1]
    plain = re.search(r'"en"\s*:\s*"([^"]+)".*?"id"\s*:\s*"([^"]+)"', text, re.S)
    if plain:
        info["en_token"] = plain.group(1)
        info["vidcore_id"] = plain.group(2)
    for endpoint in re.findall(r"https?://vidcore\.net/mo/[^\s\"'<>\\]+|/mo/[^\s\"'<>\\]+", text):
        add_unique(info["resource_urls"], normalize_url(endpoint, url))
    if "en_token" in info:
        info["note"] = "Vidcore exposes a runtime token in Next.js payload, but media generation is JS/runtime API driven."
    return info


class Resolver:
    def __init__(self, timeout: int = 20):
        self.fetcher = Fetcher(timeout)

    def resolve(self, input_url: str, use_browser: bool = False) -> ResolveResult:
        result = ResolveResult(original_url=input_url)
        result.ids.update(extract_2embed_ids(input_url))

        try:
            self._raw_resolve(input_url, result)
        except Exception as exc:
            result.errors.append(short_error(exc))
            result.step("raw_exception", input_url, note=traceback.format_exc(limit=3))

        if use_browser and not result.media_urls:
            try:
                browser_data = self._browser_observe(input_url)
                for key in ("media_urls", "iframe_urls", "resource_urls"):
                    for url in browser_data.get(key, []):
                        add_unique(getattr(result, key), url)
                result.step("browser_observer", input_url, note=browser_data.get("note", "completed"))
                if browser_data.get("errors"):
                    result.errors.extend(browser_data["errors"])
            except Exception as exc:
                result.errors.append(short_error(exc))
                result.step("browser_observer_error", input_url, note=str(exc))

        if result.media_urls:
            result.status = "resolved"
        elif result.blocked:
            result.status = "blocked"
        elif result.iframe_urls or result.embed_urls or result.resource_urls:
            result.status = "partial"
        else:
            result.status = "not_resolved"

        if result.protection_findings and not result.media_urls and not (result.iframe_urls or result.embed_urls or result.resource_urls):
            result.blocked = True
            result.status = "blocked"
        return result

    def _raw_resolve(self, input_url: str, result: ResolveResult) -> None:
        queue: List[Tuple[str, Optional[str]]] = [(input_url, None)]
        seen: Set[str] = set()
        candidate_urls = self._candidate_2embed_urls(input_url, result.ids)
        for candidate in candidate_urls:
            add_unique(queue, (candidate, input_url))

        while queue and len(seen) < 40:
            url, referer = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                status, final_url, text, headers = self.fetcher.request(url, referer=referer)
            except Exception as exc:
                result.errors.append(short_error(exc))
                result.step("fetch_error", url, note=short_error(exc))
                continue
            result.resolved_url = final_url
            result.step("fetch", url, status, f"{len(text)} chars")

            if status in (401, 403, 429, 503) and PROTECTION_RE.search(text + json.dumps(headers)):
                result.blocked = True
                add_unique(result.protection_findings, f"Protected response at {urllib.parse.urlsplit(url).netloc}: HTTP {status}")
            if PROTECTION_RE.search(text):
                add_unique(result.protection_findings, f"Protection markers found in {urllib.parse.urlsplit(url).netloc} page.")

            for media in extract_media_urls(text, final_url):
                add_unique(result.media_urls, media)
            for iframe in extract_iframes(text, final_url):
                add_unique(result.iframe_urls, iframe)
                add_unique(queue, (iframe, final_url))

            for discovered in extract_urls(text, final_url):
                if self._is_interesting_resource(discovered):
                    add_unique(result.resource_urls, discovered)
                if self._should_follow(discovered):
                    add_unique(queue, (discovered, final_url))

            parsed = urllib.parse.urlsplit(final_url)
            host = parsed.netloc.lower()
            if "vidcore.net" in host:
                info = parse_vidcore_page(final_url, text)
                result.tokens.update({k: v for k, v in info.items() if k.endswith("_token")})
                if info.get("vidcore_id"):
                    result.ids["vidcore_id"] = info["vidcore_id"]
                for media in info.get("media_urls", []):
                    add_unique(result.media_urls, media)
                for resource in info.get("resource_urls", []):
                    add_unique(result.resource_urls, resource)
                result.step("parse_vidcore", final_url, note=info.get("note", "parsed"))

            if self._looks_xfilesharing(host, text):
                details = parse_xfilesharing_page(final_url, text)
                if "dhcplay.com" in host:
                    for bridge_url in self._dhcplay_bridge_urls(final_url, details):
                        add_unique(result.iframe_urls, bridge_url)
                        if bridge_url not in seen:
                            add_unique(queue, (bridge_url, final_url))
                if details.get("media_urls") or details.get("dl_urls") or (
                    details.get("file_code") and details.get("file_code") != "p-equiv"
                ):
                    server_info = {
                        "host": host,
                        "file_code": details.get("file_code"),
                        "dl_urls_found": len(details.get("dl_urls", [])),
                        "unpacked_scripts": details.get("unpacked_scripts", 0),
                    }
                    if server_info not in result.source_servers:
                        result.source_servers.append(server_info)
                if details.get("hash"):
                    result.tokens[f"{host}_hash"] = details["hash"]
                for media in details.get("media_urls", []):
                    add_unique(result.media_urls, media)
                for dl in details.get("dl_urls", []):
                    if dl not in seen and "op=view" in dl:
                        add_unique(queue, (dl, final_url))
                result.step("parse_xfilesharing", final_url, note=f"{len(details.get('media_urls', []))} media urls")

    def _candidate_2embed_urls(self, input_url: str, ids: Dict[str, Any]) -> List[str]:
        parsed = urllib.parse.urlsplit(input_url)
        host = parsed.netloc
        imdb_id = ids.get("imdb_id")
        candidates: List[str] = []
        if imdb_id and "2embed.stream" in host:
            add_unique(candidates, f"https://www.2embed.stream/2embed.php?id={urllib.parse.quote(imdb_id)}")
            add_unique(candidates, f"https://2embed.stream/embed/movie/main_video.php?id={urllib.parse.quote(imdb_id)}")
            add_unique(candidates, f"https://2embed.stream/embed/movie/main_upcloud.php?id={urllib.parse.quote(imdb_id)}")
        return candidates

    @staticmethod
    def _is_interesting_resource(url: str) -> bool:
        if "{" in url or "}" in url:
            return False
        return bool(
            re.search(
                r"m3u8|mpd|mp4|/(?:embed|e)/|iframe\.php|videoplayback|vidcore|/dl\?|/stream/|serverusa|main_video|main_upcloud|altserver|south\.php|king_usa",
                url,
                re.I,
            )
        )

    @staticmethod
    def _should_follow(url: str) -> bool:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if "{" in url or "}" in url:
            return False
        path = parsed.path.lower()
        if parsed.fragment:
            return False
        if re.search(r"\.(css|png|jpe?g|gif|svg|woff2?|ico|ts)(?:\?|$)", parsed.path, re.I):
            return False
        host_path = parsed.netloc.lower() + path
        if re.search(r"(?:^|/)cdn-cgi/|zaraz|rocket-loader|challenge-platform", path, re.I):
            return False
        if re.search(r"2embed\.stream", parsed.netloc, re.I):
            return bool(
                re.search(
                    r"/(?:embed/(?:movie|tv)/|2embed\.php|tv-2embed\.php|videoplayback\.php|embed/movie/main_(?:video|upcloud)\.php|altserver/|serverusa|south\.php|king_usa\.php|sub/get-subtitles\.php)",
                    path,
                    re.I,
                )
            )
        if "vidcore.net" in parsed.netloc.lower():
            return bool(re.search(r"/(?:movie|tv|mo/|wyzie|hls\.worker\.js)", path, re.I))
        if re.search(r"vibuxer\.com|hanerix\.com|callistanise\.com|ryderjet\.com|dhcplay\.com", parsed.netloc, re.I):
            return bool(re.search(r"/(?:embed/|e/|dl\b|stream/)", path, re.I))
        return bool(re.search(r"/dl\?|/stream/|\.m3u8", host_path, re.I))

    @staticmethod
    def _looks_xfilesharing(host: str, text: str) -> bool:
        return bool(
            re.search(r"vibuxer|hanerix|callistanise|dhcplay", host, re.I)
            or re.search(r"jwplayer\.setup|file_code|op=view|xupload|Please disable AdBlock", text or "", re.I)
        )

    @staticmethod
    def _dhcplay_bridge_urls(url: str, details: Dict[str, Any]) -> List[str]:
        parsed = urllib.parse.urlsplit(url)
        match = re.search(r"/e/([A-Za-z0-9_-]+)", parsed.path)
        file_code = details.get("file_code") or (match.group(1) if match else None)
        if not file_code or file_code == "p-equiv":
            return []
        poster = urllib.parse.parse_qs(parsed.query).get("poster", ["https://2embed.stream/assets/images/no-bg.png"])[0]
        poster_q = urllib.parse.urlencode({"poster": poster})
        return [
            f"https://vibuxer.com/e/{urllib.parse.quote(file_code)}?{poster_q}",
            f"https://hanerix.com/e/{urllib.parse.quote(file_code)}?{poster_q}",
        ]

    def _browser_observe(self, input_url: str) -> Dict[str, Any]:
        data = {"media_urls": [], "iframe_urls": [], "resource_urls": [], "errors": []}
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            data["errors"].append("Playwright is not installed. Install with: pip install playwright && playwright install chromium")
            return data

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)

            def record(url: str) -> None:
                if extract_media_urls(url):
                    add_unique(data["media_urls"], url)
                elif self._is_interesting_resource(url):
                    add_unique(data["resource_urls"], url)

            page.on("request", lambda req: record(req.url))
            page.on("response", lambda resp: record(resp.url))
            try:
                page.goto(input_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(2500)
                for frame in page.frames:
                    if frame.url and frame.url != "about:blank":
                        add_unique(data["iframe_urls"], frame.url)
                for selector in ["button.play-button", ".play-button", "[aria-label*=Play]", "button"]:
                    try:
                        page.locator(selector).first.click(timeout=1500)
                        page.wait_for_timeout(5000)
                        break
                    except Exception:
                        pass
            except Exception as exc:
                data["errors"].append(short_error(exc))
            finally:
                browser.close()
        data["note"] = "Browser observer collected network URLs without solving CAPTCHA, login, or DRM."
        return data


class ResolveHandler(BaseHTTPRequestHandler):
    resolver = Resolver()
    redact = False

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self._send_json(
                {
                    "service": "traffic resolver test API",
                    "endpoints": ["/resolve?url=..."],
                    "default_test_url": DEFAULT_TEST_URL,
                }
            )
            return
        if parsed.path != "/resolve":
            self.send_error(404, "Use /resolve?url=...")
            return
        url = params.get("url", [DEFAULT_TEST_URL])[0]
        use_browser = params.get("browser", ["0"])[0].lower() in ("1", "true", "yes")
        redact = params.get("redact", ["0"])[0].lower() in ("1", "true", "yes") or self.redact
        result = self.resolver.resolve(url, use_browser=use_browser)
        self._send_json(result.as_dict(), redact=redact)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send_json(self, data: Any, status: int = 200, redact: Optional[bool] = None) -> None:
        if redact is None:
            redact = self.redact
        body = safe_json(data, redact=redact).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str, port: int, redact: bool = False) -> None:
    ResolveHandler.redact = redact
    server = ThreadingHTTPServer((host, port), ResolveHandler)
    print(f"Listening on http://{host}:{port}")
    print(f"Try: http://{host}:{port}/resolve?url={urllib.parse.quote(DEFAULT_TEST_URL, safe='')}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local resolver test API.")
    parser.add_argument("url", nargs="?", default=DEFAULT_TEST_URL, help="Input embed/player URL to resolve.")
    parser.add_argument("--serve", action="store_true", help="Start /resolve API server.")
    parser.add_argument("--host", default="127.0.0.1", help="API host.")
    parser.add_argument("--port", type=int, default=8088, help="API port.")
    parser.add_argument("--browser", action="store_true", help="Use Playwright browser observer fallback.")
    parser.add_argument("--redact", action="store_true", help="Redact sensitive query/token/cookie values in output.")
    args = parser.parse_args(argv)

    if args.serve:
        run_server(args.host, args.port, redact=args.redact)
        return 0

    resolver = Resolver()
    result = resolver.resolve(args.url, use_browser=args.browser)
    print(safe_json(result.as_dict(), redact=args.redact))
    return 0 if result.status in ("resolved", "partial", "blocked", "not_resolved") else 1


if __name__ == "__main__":
    raise SystemExit(main())