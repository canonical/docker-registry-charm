import logging

import pytest


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    """Build and deploy openstack-integrator in bundle"""
    charm = await ops_test.build_charm(".")
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", main_charm=charm, series="focal"
    )
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


async def test_status_messages(ops_test):
    """Validate that the status messages are correct."""
    unit = ops_test.model.applications["docker-registry"].units[0]
    assert unit.workload_status == "active"
    # note (rgildein): ignoring E999 due to flake8 failure on py35
    assert unit.workload_status_message == \
           f"Ready at {unit.public_address}:5000 (http)."  # noqa: E999


async def test_push_image(ops_test):
    """Test the push image into the registry."""
    unit = ops_test.model.applications["docker-registry"].units[0]
    action = await unit.run_action("push", image="python:3.9-slim", pull=True)
    output = await action.wait()  # wait for result
    assert output.data.get("status") == "completed"
    assert output.data.get("results", {}).get("outcome") == "success"
    assert output.data.get("results", {}).get("raw") == \
           f"pushed {unit.public_address}:5000/python:3.9-slim"


async def test_image_list(ops_test):
    """Try getting a list of images into the registry."""
    unit = ops_test.model.applications["docker-registry"].units[0]
    action = await unit.run_action("images", repository="python:3.9-slim")
    output = await action.wait()  # wait for result
    assert output.data.get("status") == "completed"
    assert "python" in output.data.get("results", {}).get("output")
    assert "3.9-slim" in output.data.get("results", {}).get("output")
