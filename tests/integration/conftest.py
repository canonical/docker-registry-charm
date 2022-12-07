import pytest
from pathlib import Path
import yaml


@pytest.fixture()
def series(request):
    metadata_file = Path(__file__).parent / ".." / ".." / "metadata.yaml"
    metadata = yaml.safe_load(metadata_file.read_text())
    return metadata["series"]
