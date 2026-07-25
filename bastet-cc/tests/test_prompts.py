from __future__ import annotations

from bastet_cc.prompts import DETECTOR_DIRS, detection_prompt


def test_every_detector_prompt_loads_as_utf8_on_windows():
    detector_ids = sorted({
        path.stem
        for directory in DETECTOR_DIRS
        if directory.exists()
        for path in directory.glob("*.md")
    })
    assert detector_ids

    detection_prompt.cache_clear()
    for detector_id in detector_ids:
        assert detection_prompt(detector_id)
