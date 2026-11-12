"""Reject unsafe ranges before acquiring/submitting any mailbox context."""
from unittest.mock import Mock

import pytest

from gnwmanager import GnW
from gnwmanager.gnw import _contexts
from gnwmanager.validation import validate_extflash_offset, validate_intflash_offset


@pytest.fixture
def gnw():
    target = GnW.__new__(GnW)
    target.backend = Mock()
    target.contexts = _contexts
    target._external_flash_size = 1024 * 1024
    target._external_flash_block_size = 4096
    target.read_uint32 = Mock(return_value=1024 * 1024)
    target.get_context = Mock(side_effect=AssertionError("mailbox acquired before validation"))
    target._with_transfer_retry = Mock(side_effect=AssertionError("transfer begun before validation"))
    return target


@pytest.mark.parametrize("validate,offset", [(validate_extflash_offset, -4096),
                                            (validate_intflash_offset, -8192)])
def test_negative_aligned_offset(validate, offset):
    with pytest.raises(ValueError):
        validate(offset)


@pytest.mark.parametrize("bank", [0, 1, 2])
@pytest.mark.parametrize("operation", ["program", "erase", "flash"])
@pytest.mark.parametrize("case", ["negative", "capacity", "past", "end"])
def test_unsafe_range_never_acquires_context(gnw, bank, operation, case):
    capacity, block = (1024 * 1024, 4096) if bank == 0 else (256 * 1024, 8192)
    gnw.read_uint32 = Mock(side_effect=lambda key: capacity if key == "flash_size" else block)
    offset = {"negative": -block, "capacity": capacity, "past": capacity + block,
              "end": capacity - block}[case]
    size = block * 2 if case == "end" else block
    with pytest.raises(ValueError):
        if operation == "erase":
            gnw.erase(bank, offset, size, blocking=False)
        else:
            getattr(gnw, operation)(bank, offset, b"x" * size)
    gnw.get_context.assert_not_called()
    gnw._with_transfer_retry.assert_not_called()


@pytest.mark.parametrize("bank", [0, 1, 2])
@pytest.mark.parametrize("operation", ["erase", "flash"])
def test_rounding_cannot_cross_capacity(gnw, bank, operation):
    capacity, block = (1024 * 1024, 4096) if bank == 0 else (256 * 1024, 8192)
    gnw.read_uint32 = Mock(side_effect=lambda key: capacity if key == "flash_size" else block)
    with pytest.raises(ValueError):
        if operation == "erase":
            gnw.erase(bank, capacity - block, block + 1)
        else:
            gnw.flash(bank, capacity - block, b"x" * (block + 1))
    gnw.get_context.assert_not_called()


@pytest.mark.parametrize("offset,size", [(-4096, 4096), (0, -1), (0, 0),
                                        (1024 * 1024, 1), (1024 * 1024 - 4096, 4097)])
def test_hash_range_rejected_before_context(gnw, offset, size):
    with pytest.raises(ValueError):
        gnw.read_hashes(offset, size)
    gnw.get_context.assert_not_called()


@pytest.mark.parametrize("bank", [1, 2])
def test_internal_program_requires_firmware_sector_multiple(gnw, bank):
    with pytest.raises(ValueError):
        gnw.program(bank, 0, b"x" * 8191)
    gnw.get_context.assert_not_called()


def test_single_program_ram_limit(gnw):
    with pytest.raises(ValueError):
        gnw.program(0, 0, b"x" * (256 * 1024 + 1))
    gnw.get_context.assert_not_called()


@pytest.mark.parametrize("bank", [0, 1, 2])
def test_empty_program_is_noop(gnw, bank):
    gnw.program(bank, 0, b"")
    gnw.get_context.assert_not_called()


@pytest.mark.parametrize("bank", [0, 1, 2])
def test_legal_last_sector_and_explicit_whole_chip_reach_context(gnw, bank):
    capacity, block = (1024 * 1024, 4096) if bank == 0 else (256 * 1024, 8192)
    gnw.read_uint32 = Mock(side_effect=lambda key: capacity if key == "flash_size" else block)
    for offset, size, whole in [(capacity - block, block, False), (0, 0, True)]:
        with pytest.raises(AssertionError, match="mailbox acquired"):
            gnw.erase(bank, offset, size, whole_chip=whole)


@pytest.mark.parametrize("bank", [0, 1, 2])
def test_partial_erase_submits_complete_sector_to_firmware(gnw, bank):
    capacity, block = (1024 * 1024, 4096) if bank == 0 else (256 * 1024, 8192)
    context = gnw.contexts[0]
    gnw.get_context = Mock(return_value=context)
    gnw.write_uint32 = Mock()
    gnw.write_memory = Mock()
    gnw.context_counter = 1
    gnw.erase(bank, capacity - block, 1, blocking=False)
    gnw.write_uint32.assert_any_call(context["erase_bytes"].address, block)
