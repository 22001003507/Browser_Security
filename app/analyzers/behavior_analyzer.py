from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from playwright.async_api import async_playwright


BEHAVIOR_TIMEOUT = 12_000


async def _analyze(url: str):

    indicators = []
    risk_points = 0

    redirects = []
    requests_seen = []
    downloads = []
    popups = []

    async with async_playwright() as p:

        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-extensions",
                "--disable-sync",
                "--no-first-run",
            ],
        )

        context = await browser.new_context(
            java_script_enabled=True,
            accept_downloads=False,
        )

        page = await context.new_page()

        # ----------------------------------------------
        # Network monitoring
        # ----------------------------------------------

        def on_request(request):
            try:
                requests_seen.append(
                    request.url
                )
            except Exception:
                pass

        def on_response(response):
            try:
                if response.request.is_navigation_request():
                    if response.url != url:
                        redirects.append(
                            response.url
                        )
            except Exception:
                pass

        page.on(
            "request",
            on_request,
        )

        page.on(
            "response",
            on_response,
        )

        # ----------------------------------------------
        # Download detection
        # ----------------------------------------------

        def on_download(download):
            downloads.append(
                download.suggested_filename
            )

        page.on(
            "download",
            on_download,
        )

        # ----------------------------------------------
        # Popup detection
        # ----------------------------------------------

        def on_popup(popup):
            popups.append(
                popup.url
            )

        page.on(
            "popup",
            on_popup,
        )

        try:

            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=BEHAVIOR_TIMEOUT,
            )

            await page.wait_for_timeout(
                2000
            )

        except Exception as exc:

            indicators.append(
                f"Browser navigation issue: {type(exc).__name__}"
            )

        # ----------------------------------------------
        # Risk evaluation
        # ----------------------------------------------

        if len(redirects) >= 2:

            risk_points += 12

            indicators.append(
                f"Multiple redirects detected ({len(redirects)})"
            )

        if len(downloads) > 0:

            risk_points += 20

            indicators.append(
                "Download attempt detected"
            )

        if len(popups) > 0:

            risk_points += 8

            indicators.append(
                "Unexpected popup detected"
            )

        unique_domains = set()

        for request_url in requests_seen:

            try:
                domain = urlparse(
                    request_url
                ).netloc.lower()

                if domain:
                    unique_domains.add(domain)

            except Exception:
                pass

        if len(unique_domains) >= 15:

            risk_points += 8

            indicators.append(
                "Large number of network domains contacted"
            )

        await context.close()
        await browser.close()

    return {
        "risk_points": min(
            risk_points,
            50,
        ),
        "indicators": indicators,
        "redirect_count": len(redirects),
        "download_count": len(downloads),
        "popup_count": len(popups),
        "request_count": len(requests_seen),
        "unique_domains": len(unique_domains),
    }


def analyze_behavior(url: str):

    try:

        return asyncio.run(
            _analyze(url)
        )

    except Exception as exc:

        return {
            "risk_points": 0,
            "indicators": [
                f"Behavior analysis unavailable: {type(exc).__name__}"
            ],
            "redirect_count": 0,
            "download_count": 0,
            "popup_count": 0,
            "request_count": 0,
            "unique_domains": 0,
        }