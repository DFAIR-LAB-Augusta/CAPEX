from __future__ import annotations

import sys

import pytest

from capex.exceptions import CommandExecutionError
from capex.runner import CommandRunner


def test_run_raises_command_execution_error_on_nonzero_exit() -> None:
    runner = CommandRunner()

    with pytest.raises(CommandExecutionError, match='exit code 1'):
        runner.run([sys.executable, '-c', 'import sys; sys.exit(1)'])


def test_run_does_not_raise_when_check_is_false() -> None:
    runner = CommandRunner()

    result = runner.run([sys.executable, '-c', 'import sys; sys.exit(1)'], check=False)

    assert result.returncode == 1


def test_run_returns_completed_command_on_success() -> None:
    runner = CommandRunner()

    result = runner.run([sys.executable, '-c', "print('hi')"])

    assert result.returncode == 0
    assert result.stdout.strip() == 'hi'
