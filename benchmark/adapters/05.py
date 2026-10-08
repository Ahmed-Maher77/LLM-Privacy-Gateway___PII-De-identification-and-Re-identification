"""05-python-presidio-bert-qwen-gateway: `privacy-gateway sanitize` defaults (Settings.from_env)."""

import itertools
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import run  # noqa: E402

warnings.simplefilter("ignore")
from privacy_gateway.config import Settings  # noqa: E402
from privacy_gateway.gateway import GatewayRequest, PrivacyGateway  # noqa: E402

gateway = PrivacyGateway(Settings.from_env())
ids = itertools.count()


def redact(text: str) -> str:
    request = GatewayRequest(text=text, conversation_id=f"bench-{next(ids)}")
    return gateway.sanitize(request).sanitized_text


run("05-python-presidio-bert-qwen-gateway", redact)
