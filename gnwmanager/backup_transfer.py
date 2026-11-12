"""Bounded HTTP download worker, supervised by full_backup's total deadline."""

import sys
from pathlib import Path
from urllib.request import urlopen


def download(url, destination, limit):
    """Stream at most limit bytes; the parent bounds DNS, headers and body time."""
    with urlopen(url, timeout=30) as response, Path(destination).open("xb") as output:
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > limit):
            raise ValueError("Transfer exceeds size limit")
        total = 0
        while True:
            chunk = response.read1(min(65536, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError("Transfer exceeds size limit")
            output.write(chunk)


def main():
    try:
        download(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    except Exception as error:
        # Keep subprocess output bounded even for malformed remote responses.
        sys.stderr.write(str(error)[:1024] + "\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
