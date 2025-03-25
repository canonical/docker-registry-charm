import logging
from pathlib import Path
import pytest
from pytest_operator.plugin import OpsTest


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test : OpsTest, series):
    """Build and deploy docker-registry in bundle"""
    charm = next(Path.cwd().glob("docker-registry*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", main_charm=charm.resolve(), series=series
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


async def test_status_messages(ops_test):
    """Validate that the status messages are correct."""
    registry_units = [
        app.units[0]
        for name, app in ops_test.model.applications.items()
        if "docker-registry" in name
    ]

    for unit in registry_units:
        assert unit.workload_status == "active"
        msg = f"Ready at {unit.public_address}:5000 (http)."
        assert unit.workload_status_message == msg


async def test_push_image(ops_test):
    """Test the push image into the registry."""
    registry_units = [
        app.units[0]
        for name, app in ops_test.model.applications.items()
        if "docker-registry" in name
    ]

    for unit in registry_units:
        action = await unit.run_action("push", image="python:3.9-slim", pull=True)
        output = await action.wait()  # wait for result
        assert output.status == "completed"
        assert output.results.get("raw") == \
            f"pushed {unit.public_address}:5000/python:3.9-slim"


async def test_image_list(ops_test):
    """Try getting a list of images into the registry."""
    registry_units = [
        app.units[0]
        for name, app in ops_test.model.applications.items()
        if "docker-registry" in name
    ]

    for unit in registry_units:
        action = await unit.run_action("images", repository="python:3.9-slim")
        output = await action.wait()  # wait for result
        assert output.status == "completed"
        assert "python" in output.results.get("output")
