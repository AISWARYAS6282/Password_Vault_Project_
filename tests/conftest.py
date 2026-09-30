import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import logger  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_logs(tmp_path):
    """Keep test log output out of the project's logs/ directory."""
    logger.configure(tmp_path / "logs")
    yield
