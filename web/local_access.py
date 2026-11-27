#!/usr/bin/env python3
"""Run on Linux Docker host. Expose container loopback to host loopback only."""
import argparse, os, socketserver, subprocess, threading
RELAY = r'''
import os, socket, threading
s=socket.create_connection(('127.0.0.1',8080))
def send():
    try:
        while True:
            b=os.read(0,65536)
            if not b: break
            s.sendall(b)
    except OSError: pass
    finally:
        try: s.shutdown(socket.SHUT_WR)
        except OSError: pass
threading.Thread(target=send,daemon=True).start()
try:
    while True:
        b=s.recv(65536)
        if not b: break
        v=memoryview(b)
        while v: v=v[os.write(1,v):]
finally: s.close()
'''
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        p=subprocess.Popen(['docker','exec','-i',self.server.container,'python3','-u','-c',RELAY],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        def send():
            try:
                while True:
                    b=self.request.recv(65536)
                    if not b: break
                    p.stdin.write(b); p.stdin.flush()
            except (OSError,ValueError): pass
            finally:
                try: p.stdin.close()
                except OSError: pass
        t=threading.Thread(target=send,daemon=True);t.start()
        try:
            while True:
                b=os.read(p.stdout.fileno(),65536)
                if not b: break
                self.request.sendall(b)
        except OSError: pass
        finally:
            p.terminate()
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill();p.wait()
            try: self.request.shutdown(2)
            except OSError: pass
            t.join(timeout=1)
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--container',default='openhands-ubuntu24');a=p.parse_args()
    with Server(('127.0.0.1',8080),Handler) as server:
        server.container=a.container
        print('Open http://127.0.0.1:8080 (local access only)',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
