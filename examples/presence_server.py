"""Example presence server for BedrockPresence.

Listens on TCP 9514 (newline-delimited JSON). For every client it logs the
hello, sends a random token (the client relays it to the game server in a
DebugInfoPacket), then pushes a Discord activity and updates it every 15s.
Mapping tokens to players is up to the real server side.

    python presence_server.py --client-id 123456789012345678
    python presence_server.py --client-id ... --tls-cert cert.pem --tls-key key.pem

Stdlib only.
"""

import argparse
import asyncio
import json
import secrets
import ssl
import time


async def send(writer: asyncio.StreamWriter, msg: dict) -> None:
    writer.write((json.dumps(msg) + "\n").encode())
    await writer.drain()


def activity(host: str, counter: int, started: int) -> dict:
    return {
        "details": f"BedrockPresence Test",
        "state": f"Update #{counter}",
        "timestamps": {"start": started},
        "assets": {"large_image": "powernukkitx", "large_text": host},
        "buttons": [{"label": "Powered by PowerNukkitX", "url": "https://powernukkitx.org"}],
    }


async def read_messages(reader: asyncio.StreamReader, peer: str) -> None:
    while line := await reader.readline():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            print(f"[{peer}] invalid line: {line!r}")
            continue
        print(f"[{peer}] <- {msg}")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_id: str, interval: float) -> None:
    peer = "%s:%s" % writer.get_extra_info("peername")[:2]
    print(f"[{peer}] connected")
    try:
        hello = json.loads(await asyncio.wait_for(reader.readline(), 10))
        print(f"[{peer}] <- {hello}")
        host = hello.get("host", "server")

        reading = asyncio.create_task(read_messages(reader, peer))

        token = secrets.token_urlsafe(16)
        await send(writer, {"type": "token", "token": token})
        print(f"[{peer}] -> token {token}")

        started = int(time.time())
        counter = 0
        while not reading.done():
            counter += 1
            msg = {"type": "activity", "activity": activity(host, counter, started)}
            if client_id:
                msg["client_id"] = client_id
            await send(writer, msg)
            print(f"[{peer}] -> activity #{counter}")
            await asyncio.wait([reading], timeout=interval)
    except (asyncio.TimeoutError, ConnectionError, json.JSONDecodeError) as e:
        print(f"[{peer}] error: {e!r}")
    finally:
        writer.close()
        print(f"[{peer}] disconnected")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9514)
    ap.add_argument("--client-id", default="1133823892486623344", help="Discord application id (omit to use the client's default_client_id)")
    ap.add_argument("--interval", type=float, default=15.0, help="seconds between activity updates")
    ap.add_argument("--tls-cert", help="PEM certificate; enables TLS (client config: \"tls\": true)")
    ap.add_argument("--tls-key", help="PEM private key for --tls-cert")
    args = ap.parse_args()

    ctx = None
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.tls_cert, args.tls_key)

    server = await asyncio.start_server(
        lambda r, w: handle(r, w, args.client_id, args.interval), args.host, args.port, ssl=ctx
    )
    print(f"listening on {args.host}:{args.port}{' (TLS)' if ctx else ''}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
