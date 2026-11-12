"""Directory errors survive mailbox release and return-to-IDLE cleanup."""
from unittest.mock import Mock

import pytest

from gnwmanager import GnW
from gnwmanager.gnw import DataError, _contexts


def target(status, data=b""):
    gnw = GnW.__new__(GnW)
    gnw.context_counter = 1
    context = _contexts[0]
    gnw.get_context = Mock(return_value=context)
    gnw.write_uint32 = Mock()
    gnw.write_str = Mock()
    gnw._drain_pending_writes = Mock()
    gnw.wait_for_context_response = Mock()
    current = {"status": status}
    gnw.read_uint32 = Mock(side_effect=lambda name: current["status"] if name == "status" else len(data))
    gnw.read_memory = Mock(return_value=data)
    gnw.wait_for_idle = Mock(side_effect=lambda: current.update(status=0))
    return gnw, context


@pytest.mark.parametrize("status,message", [(0xBAD00007, "BAD_SD_FS_MOUNT"),
                                           (0xBAD0000B, "BAD_SD_DIR")])
def test_saved_directory_error_raised_after_cleanup(status, message):
    gnw, context = target(status)
    with pytest.raises(DataError, match=message):
        gnw.sd_list_dir("/missing")
    gnw.write_uint32.assert_any_call(context["ready"], 0)
    gnw.wait_for_idle.assert_called_once()
    gnw.read_uint32.assert_any_call("status")
    # The released context can service another directory request after failure.
    assert gnw.sd_list_dir("/") == ""
    assert gnw.context_counter == 3


def test_truncated_directory_is_returned_after_cleanup(caplog):
    gnw, _ = target(0xBAD0000C, b"partial\n")
    assert gnw.sd_list_dir("/") == "partial\n"
    assert "truncated" in caplog.text
    gnw.wait_for_idle.assert_called_once()


def test_successful_directory_returns_actual_data():
    gnw, _ = target(0, b"file.bin\n")
    assert gnw.sd_list_dir("/") == "file.bin\n"
