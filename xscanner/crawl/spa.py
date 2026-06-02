from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from playwright.async_api import Page, async_playwright


@dataclass(slots=True)
class SpaCrawlResult:
    routes: set[str] = field(default_factory=set)
    api_endpoints: set[str] = field(default_factory=set)
    graphql_endpoints: set[str] = field(default_factory=set)
    js_routes: set[str] = field(default_factory=set)


def _same_origin(url: str, origin: str) -> bool:
    return urlsplit(url).netloc == urlsplit(origin).netloc


def _clean_url(url: str) -> str:
    s = urlsplit(url)
    q = "&".join(sorted(f"{k}={v}" if v else k for k, v in parse_qsl(s.query, keep_blank_values=True)))
    return urlunsplit((s.scheme, s.netloc, s.path or "/", q, ""))


async def _auto_scroll(page: Page, rounds: int = 6) -> None:
    for _ in range(rounds):
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(0.5)


async def _extract_links(page: Page, base_url: str) -> set[str]:
    links: list[str] = await page.evaluate(
        """() => {
            const out = new Set();
            for (const a of document.querySelectorAll('a[href]')) out.add(a.href);
            const walker = document.createTreeWalker(document, NodeFilter.SHOW_ELEMENT);
            while (walker.nextNode()) {
                const el = walker.currentNode;
                if (el.shadowRoot) {
                    for (const s of el.shadowRoot.querySelectorAll('a[href]')) out.add(s.href);
                }
            }
            return Array.from(out);
        }"""
    )
    return {_clean_url(urljoin(base_url, u)) for u in links if u}


async def crawl_spa(seed_urls: Iterable[str], max_pages: int = 30, timeout_ms: int = 12000) -> SpaCrawlResult:
    result = SpaCrawlResult()
    queue = deque(_clean_url(u) for u in seed_urls)
    visited: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()

        async def scan_single(url: str) -> None:
            page = await context.new_page()
            page_api: set[str] = set()
            page_graphql: set[str] = set()
            page_js_routes: set[str] = set()

            def on_request(req):
                rurl = req.url
                page_api.add(_clean_url(rurl))
                low = rurl.lower()
                if 'graphql' in low or req.method == 'POST' and req.headers.get('content-type', '').startswith('application/json'):
                    try:
                        payload = req.post_data_json
                        if isinstance(payload, dict) and ('query' in payload or 'operationName' in payload):
                            page_graphql.add(_clean_url(rurl))
                    except Exception:
                        if 'graphql' in low:
                            page_graphql.add(_clean_url(rurl))

            def on_response(resp):
                ctype = (resp.headers or {}).get('content-type', '')
                if 'javascript' in ctype and resp.url:
                    page_js_routes.add(_clean_url(resp.url))

            page.on('request', on_request)
            page.on('response', on_response)
            await page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
            await page.wait_for_timeout(700)
            await _auto_scroll(page)
            await page.evaluate(
                """() => {
                  const clickables = Array.from(document.querySelectorAll('a,button,[role="button"]')).slice(0, 40);
                  for (const el of clickables) { try { el.dispatchEvent(new MouseEvent('click', {bubbles:true,cancelable:true})); } catch(e) {} }
                }"""
            )
            await page.wait_for_timeout(700)
            current = _clean_url(page.url)
            result.routes.add(current)

            # SPA route extraction hooks
            route_dump = await page.evaluate(
                """() => {
                const out = new Set();
                if (window.__NEXT_DATA__?.page) out.add(location.origin + window.__NEXT_DATA__.page);
                if (window.$nuxt?._route?.fullPath) out.add(location.origin + window.$nuxt._route.fullPath);
                const scripts = [...document.scripts].map(s => s.src || '').filter(Boolean);
                return {scripts, pathname: location.pathname};
                }"""
            )
            result.routes.add(_clean_url(urljoin(url, route_dump.get('pathname', '/'))))
            for s in route_dump.get('scripts', []):
                page_js_routes.add(_clean_url(urljoin(url, s)))
            result.api_endpoints |= {u for u in page_api if _same_origin(u, url)}
            result.graphql_endpoints |= {u for u in page_graphql if _same_origin(u, url)}
            result.js_routes |= {u for u in page_js_routes if _same_origin(u, url)}

            for link in await _extract_links(page, url):
                if _same_origin(link, url):
                    result.routes.add(link)
            await page.close()

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                await scan_single(url)
            except Exception:
                continue
            for nxt in sorted(result.routes):
                if nxt not in visited and len(visited) + len(queue) < max_pages:
                    queue.append(nxt)

        await context.close()
        await browser.close()

    return result
