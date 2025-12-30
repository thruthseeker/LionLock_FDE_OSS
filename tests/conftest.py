import pytest

from lionlock.logging import sql_telemetry


@pytest.fixture(autouse=True)
def _stop_sql_telemetry_writer() -> None:
    yield
    sql_telemetry.stop_writer()
