"""01-python-gliner-spacy-gateway: PIIMiddleware as generate_report.py builds it."""

import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import run  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "01-python-gliner-spacy-gateway"))
warnings.simplefilter("ignore")
from pii import PIIMiddleware  # noqa: E402

middleware = PIIMiddleware(on_leak="warn")
run("01-python-gliner-spacy-gateway", lambda text: middleware.analyze(text).sanitized)
