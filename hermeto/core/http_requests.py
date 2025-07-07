# SPDX-License-Identifier: GPL-3.0-or-later
from requests import Session
from requests.adapters import HTTPAdapter, Retry


def get_requests_session() -> Session:
    """Create a requests session with various retry options."""
    session = Session()
    adapter = HTTPAdapter(
        max_retries=Retry(
            connect=5,
            total=5,
            read=5,
            allowed_methods=["GET", "HEAD", "OPTIONS", "TRACE"],
            status_forcelist=(500, 502, 503, 504),
            backoff_factor=1.3,
        )
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
