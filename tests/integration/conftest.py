import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--series",
        type=str,
        default="focal",
        help="Set series for the machine units",
    )


@pytest.fixture()
def series(request):
    return request.config.getoption("--series")
