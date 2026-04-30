from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin

EXECUTION_MARKER = "WAF_UPLOAD_VULN_DETECTED"


class UploadPathExtractor(HTMLParser):
    """
    Lightweight HTML extractor for uploaded file paths.
    """

    _CANDIDATE_ATTRS = ("href", "src", "action", "value", "data-url", "data-file")

    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename = filename.lower()
        self.paths: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if value is None:
                continue
            if key.lower() not in self._CANDIDATE_ATTRS:
                continue
            self._add_if_match(value)

    def handle_data(self, data: str) -> None:
        self._add_if_match(data)

    def _add_if_match(self, value: str) -> None:
        raw = unescape(value).strip().strip("'\"")
        if not raw:
            return
        if self.filename not in raw.lower():
            return
        self.paths.add(raw)


def extract_dynamic_verify_urls(base_url: str, response_text: str, filename: str) -> list[str]:
    extractor = UploadPathExtractor(filename=filename)
    extractor.feed(response_text)

    escaped_filename = re.escape(filename)
    for match in re.findall(
        rf"([^\s\"'<>]+{escaped_filename}[^\s\"'<>]*)",
        response_text,
        re.IGNORECASE,
    ):
        extractor.paths.add(unescape(match).strip().strip("'\""))

    verify_urls: list[str] = []
    for path in extractor.paths:
        if not path:
            continue
        if path.startswith(("http://", "https://")):
            verify_urls.append(path)
            continue
        normalized = path if path.startswith("/") else f"/{path.lstrip('./')}"
        verify_urls.append(urljoin(base_url, normalized))
    return verify_urls

