"""Optional installed desktop integration must target this project."""
import configparser
from pathlib import Path
import shlex
import pytest


def test_desktop_launcher_points_to_project():
    root = Path(__file__).resolve().parents[1]
    config = configparser.ConfigParser(interpolation=None)
    launcher = root.parent / 'PacketMap.desktop'
    if not launcher.exists():
        pytest.skip('Desktop launcher is an optional machine-local integration.')
    config.read(launcher)
    entry = config['Desktop Entry']
    assert Path(entry['Path']) == root
    assert shlex.split(entry['Exec']) == [str(root / 'run.sh')]
    assert (root / 'run.sh').is_file()
