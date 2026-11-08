#!/usr/bin/env python3
"""Integration test: python3 tests/endian.py /path/to/built/opennap.

Starts a loopback-only server with a disposable user database. No dependencies
outside Python's standard library; never connects to a production server.
"""
import contextlib
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time


def frame(order, tag, body=b""):
    if isinstance(body, str):
        body = body.encode("ascii")
    return struct.pack(order + "HH", len(body), tag) + body


class Client:
    def __init__(self, port, order):
        self.order = order
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def close(self):
        self.sock.close()

    def send(self, tag, body=b"", fragmented=False):
        data = frame(self.order, tag, body)
        if fragmented:
            for byte in data:
                self.sock.sendall(bytes([byte]))
                time.sleep(0.002)
        else:
            self.sock.sendall(data)

    def exact(self, count):
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise EOFError("server closed before the expected reply")
            data += chunk
        return data

    def receive(self):
        size, tag = struct.unpack(self.order + "HH", self.exact(4))
        assert size <= 4096, ("incorrect reply length/byte order", size, tag)
        return tag, self.exact(size)

    def until(self, expected):
        seen = []
        for _ in range(40):
            tag, body = self.receive()
            seen.append((tag, body))
            if tag == expected:
                return body, seen
        raise AssertionError((expected, seen))

    def closed(self):
        try:
            assert self.sock.recv(1) == b"", "expected disconnection"
        except ConnectionResetError:
            pass


def login_body(nick):
    return f'{nick} testpass 0 "v2.0 BETA 10.4" 3 test@example.invalid'


def run(binary):
    with tempfile.TemporaryDirectory(prefix="opennap-endian-") as directory:
        root = pathlib.Path(directory)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = root / "config"
        config.write_text(
            f"config_dir {root}\nserver_name endian.test\n"
            "listen_addr 127.0.0.1\nstats_port 0\n"
            "max_clones 0\nflood_commands 0\nstat_click 3600\n"
            "max_command_length 2048\n"
        )
        (root / "motd").write_text("endian first line\nendian second line\n")
        (root / "users").touch()
        with (root / "log").open("w+") as log:
            process = subprocess.Popen(
                [str(binary), "-c", str(config), "-l", "127.0.0.1", "-p", str(port)],
                stdout=log, stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("server exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), 0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                else:
                    raise RuntimeError("server did not start")
                with contextlib.ExitStack() as stack:
                    def client(order):
                        c = Client(port, order)
                        stack.callback(c.close)
                        return c

                    for order, suffix in (("<", "le"), (">", "be")):
                        c = client(order)
                        # The captured BE version check starts 00 10 00 04.
                        c.send(4, '"v2.0 BETA 10.4"', fragmented=True)
                        c.send(7, "new" + suffix, fragmented=True)
                        assert c.receive() == (8, b"")
                        c.send(6, login_body("new" + suffix), fragmented=True)
                        assert c.receive()[0] == 3
                        _, motd = c.until(214)
                        lines = [body for tag, body in motd if tag == 621]
                        assert b"endian first line" in lines, lines
                        assert b"endian second line" in lines, lines
                        c.close()
                        time.sleep(0.05)
                        # Retry connections may start with command 11, not 4.
                        c = client(order)
                        c.send(11, "new" + suffix + " testpass", fragmented=True)
                        assert c.receive() == (12, b"")
                        c.send(2, login_body("new" + suffix))
                        assert c.receive()[0] == 3
                        c.until(214)
                        c.close()
                        print(suffix + ": fragmented registration, existing login, batched MOTD passed")

                        # Detect from command 7 alone, as in the captured retry.
                        c = client(order)
                        c.send(7, "new" + suffix)
                        assert c.receive() == (9, b"")
                        c.send(7, "bad!nick!")
                        assert c.receive() == (10, b"")
                        c.close()

                        # A first command 6 and two coalesced input frames.
                        c = client(order)
                        c.sock.sendall(frame(order, 6, login_body("batch" + suffix)) + frame(order, 214))
                        assert c.receive()[0] == 3
                        c.until(214)
                        c.until(214)
                        c.close()

                        # Direct command 2, without a preceding version check.
                        c = client(order)
                        c.send(2, login_body("direct" + suffix))
                        assert c.receive()[0] == 3
                        c.close()

                        # Command 300 has a tag with a nonzero high byte.
                        c = client(order)
                        c.sock.sendall(frame(order, 300, "0") + frame(order, 7, "unused"))
                        assert c.receive() == (8, b"")
                        c.close()

                        # At the length limit is accepted; one byte over closes
                        # immediately, without waiting for a declared body.
                        c = client(order)
                        c.send(4, b"x" * 2048)
                        c.send(7, "unused")
                        assert c.receive() == (8, b"")
                        c.sock.sendall(struct.pack(order + "HH", 2049, 4))
                        c.closed()
                        c.close()
                        c = client(order)
                        c.sock.sendall(struct.pack(order + "HH", 2049, 4))
                        c.closed()
                        c.close()
                        print(suffix + ": direct/coalesced commands, nickname replies, length limit passed")

                    # Alternate recipient orders to catch shared-buffer mutation.
                    mixed = []
                    for index, order in enumerate((">", "<", ">", "<")):
                        c = client(order)
                        c.send(2, login_body("mixed" + str(index)))
                        assert c.receive()[0] == 3
                        c.until(214)
                        c.send(400, "#endian")
                        c.until(405)
                        mixed.append(c)
                    for index, sender in enumerate(mixed):
                        message = "broadcast" + str(index)
                        sender.send(402, "#endian " + message)
                        for recipient in mixed:
                            body, _ = recipient.until(403)
                            assert body == f"#endian mixed{index} {message}".encode(), body
                    # Private-message payloads are never byte-swapped.
                    mixed[0].send(205, "mixed1 payload-1234")
                    body, _ = mixed[1].until(205)
                    assert body == b"mixed0 payload-1234", body
                    print("mixed: bidirectional broadcasts and private message passed")

                    # The initial decision stays fixed for this TCP connection.
                    for order, other in ((">", "<"), ("<", ">")):
                        c = client(order)
                        c.send(7, "unused")
                        assert c.receive() == (8, b"")
                        c.sock.sendall(frame(other, 4, '"v2.0 BETA 10.4"'))
                        c.closed()
                    # A BE client cannot enter the LE compressed server protocol.
                    c = client(">")
                    c.send(7, "unused")
                    assert c.receive() == (8, b"")
                    c.send(10010)
                    c.closed()
                    assert process.poll() is None
                    print("connection order stays fixed; BE server-link transition rejected")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    print("all endian integration tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run(pathlib.Path(sys.argv[1]).resolve())
