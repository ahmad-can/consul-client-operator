#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
PRINCIPAL_CHARM = "ubuntu"
APP_NAME = METADATA["name"]


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # Build and deploy charm from local source folder
    charm = await ops_test.build_charm(".")

    # Deploy the charm and wait for active/idle status
    await ops_test.model.deploy(
        PRINCIPAL_CHARM, application_name=PRINCIPAL_CHARM, base="ubuntu@22.04"
    )
    await ops_test.model.deploy(charm, application_name=APP_NAME, base="ubuntu@22.04", num_units=0)
    await ops_test.model.integrate(APP_NAME, PRINCIPAL_CHARM)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=1000)
