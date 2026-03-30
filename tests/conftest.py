from pathlib import Path

import pytest

from tests.support import fixture_relative_path, iter_sbom_fixtures


@pytest.fixture(params=iter_sbom_fixtures(), ids=lambda path: str(fixture_relative_path(path)))
def sbom_fixture_path(request: pytest.FixtureRequest) -> Path:
    return request.param
