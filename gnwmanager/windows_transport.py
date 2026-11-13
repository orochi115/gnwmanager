"""Authenticated loopback endpoints for the Windows desktop session bridge."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

_ACL_SCRIPT = r"""
$ErrorActionPreference='Stop'
$p=$env:GNW_PRIVATE_PATH
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($env:GNW_PRIVATE_CREATE -eq '1' -and !(Test-Path -LiteralPath $p)) {
  [System.IO.Directory]::CreateDirectory($p) | Out-Null
  $acl=New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true,$false)
  foreach($id in @($sid, [System.Security.Principal.SecurityIdentifier]'S-1-5-18')) {
    $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $p -AclObject $acl
}
$item=Get-Item -LiteralPath $p -Force
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Reparse points are not private manager resources'}
$acl=Get-Acl -LiteralPath $p
if($acl.Owner -ne $sid.Value -and ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {throw 'Manager path owner differs'}
foreach($rule in $acl.Access) {
  $id=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  if($rule.AccessControlType -eq 'Allow' -and $id -ne $sid.Value -and $id -ne 'S-1-5-18') {throw 'Manager path has a foreign access grant'}
}
"""

def private_windows_path(path, *, create=False):
    from gnwmanager.session_client import SessionError
    try:
        subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
             base64.b64encode(_ACL_SCRIPT.encode('utf-16le')).decode('ascii')],
            env={**os.environ, 'GNW_PRIVATE_PATH': str(path), 'GNW_PRIVATE_CREATE': '1' if create else '0'},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SessionError('INVALID_REQUEST', 'Windows manager path is not private to the current user') from error


def endpoint_credential(path):
    from gnwmanager.session_client import SessionError
    private_windows_path(path)
    before=Path(path).lstat()
    with open(path, 'rb') as stream:
        opened=os.fstat(stream.fileno())
        data=stream.read(1025)
    after=Path(path).lstat()
    if before.st_ino != opened.st_ino or before.st_dev != opened.st_dev or before.st_ino != after.st_ino or len(data)>1024:
        raise SessionError('INVALID_REQUEST','Windows manager endpoint changed or is oversized')
    try:
        value=json.loads(data)
        valid=(set(value)=={'format','port','token','pid'} and type(value['format']) is int and value['format']==1
               and type(value['pid']) is int and 1<=value['pid']<=2147483647
               and type(value['port']) is int and 1<=value['port']<=65535
               and isinstance(value['token'],str) and len(value['token'])==64
               and all(c in '0123456789abcdef' for c in value['token']))
    except (ValueError,TypeError,KeyError):
        valid=False
    if not valid:
        raise SessionError('INVALID_REQUEST','Invalid Windows manager endpoint')
    return value


def connect_endpoint(path, timeout):
    if os.name != 'nt':
        peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        peer.settimeout(timeout)
        try:peer.connect(str(path))
        except BaseException:peer.close();raise
        return peer
    credential=endpoint_credential(path)
    rows=subprocess.check_output(['netstat.exe','-ano','-p','tcp'],text=True,
                                 timeout=5,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).splitlines()
    owned=any(len(parts)==5 and parts[0]=='TCP' and parts[1]==f"127.0.0.1:{credential['port']}"
              and parts[3]=='LISTENING' and parts[4]==str(credential['pid'])
              for parts in (row.split() for row in rows))
    if not owned:
        from gnwmanager.session_client import SessionError
        raise SessionError('STALE_SESSION','Windows manager listener no longer belongs to its owning process')
    peer=socket.create_connection(('127.0.0.1',credential['port']), timeout=timeout)
    peer.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    try:
        peer.sendall(credential['token'].encode('ascii'))
        if endpoint_credential(path)!=credential:
            raise OSError('Windows manager endpoint changed during connection')
    except BaseException:
        peer.close();raise
    return peer


def debugger_target(endpoint):
    if os.name != 'nt':
        return f'target remote {endpoint}'
    command=subprocess.list2cmdline([sys.executable,'-m','gnwmanager.windows_transport',str(endpoint)])
    return f'target remote | {command}'


def main():
    """GDB pipe transport: credentials never appear in GDB's command line."""
    if len(sys.argv)!=2:
        raise SystemExit('usage: python -m gnwmanager.windows_transport ENDPOINT')
    # GDB stdin/stdout are binary RSP channels on Windows.
    if os.name=='nt':
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(),os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(),os.O_BINARY)
    peer=connect_endpoint(Path(sys.argv[1]),5)
    peer.settimeout(None)
    def from_gdb():
        try:
            while True:
                data=os.read(sys.stdin.fileno(),65536)
                if not data:break
                peer.sendall(data)
        finally:
            try:peer.shutdown(socket.SHUT_WR)
            except OSError:pass
    threading.Thread(target=from_gdb,daemon=True).start()
    try:
        while True:
            data=peer.recv(65536)
            if not data:break
            sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
    finally:peer.close()

if __name__=='__main__':main()
