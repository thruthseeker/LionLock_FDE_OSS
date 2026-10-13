import pytest

from lionlock.logging import sql_telemetry
from lionlock.trust_overlay import sql_sink


@pytest.fixture(autouse=True)
def _stop_sql_writers() -> None:
    yield
    sql_telemetry.stop_writer()
    sql_sink.stop_writer()
