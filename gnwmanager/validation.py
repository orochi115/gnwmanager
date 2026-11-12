def validate_extflash_offset(val):
    if val < 0:
        raise ValueError("Extflash offset cannot be negative.")
    if val >= 0x9000_0000:
        raise ValueError(f"Provided extflash offset 0x{val:08X}, did you mean 0x{(val - 0x9000_0000):08X} ?")
    if val % 4096 != 0:
        raise ValueError("Extflash offset must be a multiple of 4096.")


def validate_intflash_offset(val):
    if val < 0:
        raise ValueError("Intflash offset cannot be negative.")
    if val >= 0x8100_0000:
        raise ValueError(f"Provided intflash offset 0x{val:08X}, did you mean 0x{(val - 0x8100_0000):08X} ?")
    if val >= 0x8000_0000:
        raise ValueError(f"Provided intflash offset 0x{val:08X}, did you mean 0x{(val - 0x8000_0000):08X} ?")
    if val % 8192 != 0:
        raise ValueError("Intflash offset must be a multiple of 8192.")


def validate_flash_range(offset, size, capacity, *, erase_block=1):
    """Validate both the requested bytes and any rounded erase coverage."""
    if size < 0:
        raise ValueError("Flash size cannot be negative.")
    if offset < 0 or offset >= capacity:
        raise ValueError("Flash offset is outside the bank.")
    rounded_size = ((size + erase_block - 1) // erase_block) * erase_block
    if offset + rounded_size > capacity:
        raise ValueError("Flash range exceeds bank capacity.")
