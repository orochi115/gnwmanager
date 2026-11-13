import json
import socket
import threading
import pytest
from gnwmanager import windows_transport as transport
from gnwmanager.session_client import SessionError


def test_invalid_endpoint_never_connects(tmp_path, monkeypatch):
    monkeypatch.setattr(transport, 'private_windows_path', lambda path: None)
    path=tmp_path/'endpoint.sock'
    for value in [
        {'format':1,'port':1234,'pid':1234,'token':'a'*63},
        {'format':1,'port':0,'pid':1234,'token':'a'*64},
        {'format':True,'port':1234,'pid':1234,'token':'a'*64},
        {'format':1,'port':1234,'pid':1234,'token':'a'*64,'host':'external'},
    ]:
        path.write_text(json.dumps(value))
        with pytest.raises(SessionError, match='Invalid Windows manager endpoint'):
            transport.endpoint_credential(path)


def test_windows_connection_authenticates_before_rsp(tmp_path, monkeypatch):
    monkeypatch.setattr(transport, 'private_windows_path', lambda path: None)
    # Switch only this module; leave global os.name and pathlib unchanged.
    class WindowsOS:
        name='nt'
        fstat=staticmethod(transport.os.fstat)
    monkeypatch.setattr(transport,'os',WindowsOS)
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen()
    monkeypatch.setattr(transport.subprocess,'check_output',lambda *a,**kw: f"TCP 127.0.0.1:{listener.getsockname()[1]} 0.0.0.0:0 LISTENING 1234")
    token='a'*64
    path=tmp_path/'endpoint.sock'
    path.write_text(json.dumps({'format':1,'port':listener.getsockname()[1],'pid':1234,'token':token}))
    received=[]
    def peer():
        sock,_=listener.accept()
        with sock:
            data=bytearray()
            while len(data)<64: data.extend(sock.recv(64-len(data)))
            received.append(bytes(data))
            received.append(sock.recv(32))
    worker=threading.Thread(target=peer);worker.start()
    try:
        with transport.connect_endpoint(path,1) as sock:sock.sendall(b'$qSupported#37')
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert received==[token.encode(),b'$qSupported#37']
    finally:listener.close()
