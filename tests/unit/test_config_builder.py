# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for config_builder module."""

from pathlib import Path
from unittest.mock import patch

import pytest

import config_builder
from config_builder import ConsulConfigBuilder, Ports

PACKAGED_SCRIPT = Path(config_builder.__file__).parent / "tcp_health_check.py"


@pytest.fixture
def builder(tmp_path):
    destination = tmp_path / "consul" / "data" / "tcp_health_check.py"
    with patch.object(
        ConsulConfigBuilder,
        "consul_health_check",
        new_callable=lambda: property(lambda s: destination),
    ):
        yield (
            ConsulConfigBuilder(
                bind_address=None,
                datacenter="dc",
                health_check=True,
                snap_name="consul-client",
                consul_servers=["10.0.0.1:8301"],
                ports=Ports(),
            ),
            destination,
        )


def test_script_is_copied_when_missing(builder):
    config, destination = builder

    config._write_health_check_script()

    assert destination.read_bytes() == PACKAGED_SCRIPT.read_bytes()


def test_outdated_script_is_replaced(builder):
    """A charm upgrade must roll out a changed health check script."""
    config, destination = builder
    destination.parent.mkdir(parents=True)
    destination.write_text("# old version of the health check\n")

    config._write_health_check_script()

    assert destination.read_bytes() == PACKAGED_SCRIPT.read_bytes()


def test_identical_script_is_not_rewritten(builder):
    config, destination = builder
    destination.parent.mkdir(parents=True)
    destination.write_bytes(PACKAGED_SCRIPT.read_bytes())

    with patch("config_builder.shutil.copy") as copy:
        config._write_health_check_script()

    copy.assert_not_called()


def test_replacing_the_script_leaves_no_temporary_file(builder):
    config, destination = builder
    destination.parent.mkdir(parents=True)
    destination.write_text("# old version of the health check\n")

    config._write_health_check_script()

    assert [p.name for p in destination.parent.iterdir()] == [destination.name]


def test_failed_copy_keeps_the_old_script(builder):
    config, destination = builder
    destination.parent.mkdir(parents=True)
    destination.write_text("# old version of the health check\n")

    with patch("config_builder.shutil.copy", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            config._write_health_check_script()

    assert destination.read_text() == "# old version of the health check\n"
