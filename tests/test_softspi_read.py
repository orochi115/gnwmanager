"""Compile the actual read routine with deterministic SD wire primitives."""
from pathlib import Path
import subprocess

import pytest

SOURCE = Path(__file__).parents[1] / "Core/Src/FatFs/user_diskio_softspi.c"


def function(source, declaration):
    start = source.index(declaration)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


@pytest.fixture(scope="module")
def reader(tmp_path_factory):
    directory = tmp_path_factory.mktemp("softspi-wire")
    source = SOURCE.read_text()
    routines = function(source, "DRESULT USER_SOFTSPI_read(")
    if "static bool receive_read_block(" in source:
        routines = function(source, "static bool receive_read_block(") + "\n" + routines
    harness = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t BYTE;
typedef uint32_t DWORD;
typedef unsigned UINT;
typedef int DRESULT;
#define RES_OK 0
#define RES_ERROR 1
#define RES_PARERR 4
#define RES_NOTRDY 3
#define STA_NOINIT 1
#define CT_BLOCK 8
#define BLOCK_SIZE 512
#define START_BLOCK_TOKEN 0xfe
#define READ_SINGLE_BLOCK 4
#define READ_MULTIPLE_BLOCK 5
#define SEND_STOP_TRANSMISSION 3
static uint8_t Stat, CardType = CT_BLOCK;
static struct { void *spi; } sd;
static uint8_t wire[4096];
static unsigned available, position, switches, stops, ticks;
static int mode, selected;
static void SELECT(void) { selected = 1; }
static void DESELECT(void) { selected = 0; }
static void switch_ospi_gpio(int ospi) { switches = switches * 10 + (ospi ? 2 : 1); }
static void wdog_refresh(void) {}
static void timer_on(uint8_t timer, uint32_t ms) { (void)timer; (void)ms; ticks = 0; }
static uint8_t timer_status(uint8_t timer) { (void)timer; return ++ticks < 20; }
static void SoftSpi_WriteDummyRead(void *spi, uint8_t *out, uint32_t len) {
    (void)spi;
    for (unsigned i=0; i<len; i++) {
        uint8_t value = position < available ? wire[position++] : 0xff;
        if (out) out[i] = value;
    }
}
static void finish_read_cmd(void) { SoftSpi_WriteDummyRead(sd.spi, NULL, 2); }
static uint8_t SD_ReadyWait(void) { return 0xff; }
static void append(uint8_t byte, unsigned count) { while (count--) wire[available++] = byte; }
struct response { uint64_t r0; };
static struct response send_cmd(unsigned command, uint32_t sector) {
    (void)sector;
    if (command == SEND_STOP_TRANSMISSION) { stops++; return (struct response){mode==6}; }
    if (mode == 5 || mode == 8) return (struct response){1};
    available = position = 0;
    for (unsigned block=0; block < (command==READ_SINGLE_BLOCK ? 1 : 2); block++) {
        append(0xff, block ? 2 : 3);
        if (mode==4) { available=position=0; break; }
        if (((mode==2 || mode==7) && block==0) || (mode==3 && block==1)) { append(0x0b,1); break; }
        append(0xfe,1);
        for (unsigned i=0;i<512;i++) append((i * 37 + block * 101) & 255,1);
        append(0xaa,1); append(0xbb,1);
    }
    return (struct response){0};
}
'''
    main = r'''
int main(int argc, char **argv) {
    (void)argc; mode=atoi(argv[1]);
    uint8_t result[1024]; memset(result,0xcc,sizeof(result));
    unsigned count=(mode==1 || mode==7 || mode==8) ? 1 : 2;
    DRESULT status=USER_SOFTSPI_read(0,result,123,count);
    if ((mode<=1 && status!=RES_OK) || (mode>=2 && status!=RES_ERROR)) return 10;
    if (selected || switches!=12) return 11;
    if (count>1 && mode!=5 && stops!=1) return 12;
    if (count==1 && stops) return 14;
    if (mode<=1) for(unsigned block=0;block<count;block++) for(unsigned i=0;i<512;i++)
        if(result[block*512+i] != ((i*37+block*101)&255)) return 13;
    puts("read protocol and cleanup verified"); return 0;
}
'''
    path = directory / "read.c"
    path.write_text(harness + routines + main)
    binary = directory / "read"
    subprocess.run(["cc", "-std=c11", "-O0", str(path), "-o", str(binary)], check=True,
                   capture_output=True)
    return binary


@pytest.mark.parametrize("mode", [0, 1, 2, 3, 4, 5, 6, 7, 8], ids=[
    "multi-distinct-blocks-delayed-token", "single", "first-error-token",
    "second-error-token", "token-timeout", "command-error", "stop-error",
    "single-error-token", "single-command-error"])
def test_real_read_routine_protocol_and_cleanup(reader, mode):
    completed = subprocess.run([str(reader), str(mode)], capture_output=True, timeout=1)
    assert completed.returncode == 0, (mode, completed.returncode, completed.stderr)
