# BedrockPresence
Discord Rich Presence driven by the Minecraft server you are playing on. A DLL injected into `Minecraft.Windows.exe` (GDK build) notices when the game connects to a server and opens a TCP connection to the same host on port 9514. The server sends JSON lines over that socket, and the DLL shows them as your Discord activity.

Everything runs on the client. The server only needs a TCP listener on 9514, and the game protocol is unchanged.

## How it works
- **Server detection** uses Winsock hooks inside the game:
  - RakNet: outgoing Open Connection Request 1/2.
  - NetherNet: the `POST /v1/join/<id>` HTTP request to the game port, then DTLS over UDP.
- **Hostname.** The link connects to the name you joined, not its IP, so reverse proxies and several subdomains on one IP still work. The name comes from, in order:
  1. RakNet: the `ServerAddress` field in the client's Login packet. NetherNet: the HTTP `Host:` header of the join request.
  2. The game's own DNS lookups (`getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExW`).
  3. The raw IP, when you joined by IP.
- **Default presence.** Without server activity, the DLL shows `default_presence`: `idle` in menus, singleplayer and anything it doesn't detect as a server; `server` on a server that sends no activity (or while the link is down). A server `clear` returns to the default.
- **Disconnects** close the presence link immediately and clear the activity:
  - A RakNet Disconnect Notification, sent (leave) or received (kick).
  - A DTLS alert (NetherNet).
  - The game closing the socket.
  - No traffic from the server for `disconnect_timeout_ms`.
- **Retries.** A failed connection is retried every `retry_interval_ms` (30s). After `popup_after_failures` (3) failures in a row a warning popup appears, and retrying continues.
- **Token relay.** The server can send a `token`. The DLL sends it to the game server inside a `DebugInfoPacket` (id 155) through the game's own `BatchedNetworkPeer::sendPacket`, so the server can map the TCP connection to a player.

## Setup
Keep `bedrock_presence.dll`, `bedrock_presence_injector.exe` and (optionally) `config.json` in one folder. Start Minecraft, then:

```powershell
.\bedrock_presence_injector.exe
```

Re-inject after each game restart. Discord must be running.

## Config (`config.json` next to the DLL, created with defaults)
| Key | Default | Meaning |
|---|---|---|
| `port` | `9514` | Presence port on the server host |
| `default_client_id` | `""` | Discord application id used when a message has no `client_id` |
| `disconnect_timeout_ms` | `10000` | No server traffic for this long = disconnected |
| `retry_interval_ms` | `30000` | Wait between connection attempts |
| `popup_after_failures` | `3` | Failed attempts in a row before the popup |
| `tls` | `false` | Encrypt the link (TLS 1.2, Windows SChannel) |
| `tls_verify` | `true` | Check the certificate against the Windows trust store and hostname |
| `tls_pin_sha256` | `""` | Accept exactly this certificate (hex SHA-256 of the DER cert, colons allowed), for self-signed certs. Overrides `tls_verify` |
| `default_presence.client_id` | `""` | Discord application id for the default presence; empty = `default_client_id`; both empty = off |
| `default_presence.idle` | `{"details":"In the menus"}` | Activity with no server connection (menus, singleplayer). Any Discord activity field ([list](docs/SERVER.md#activity-fields)). `null` = nothing |
| `default_presence.server` | `{"details":"Playing multiplayer"}` | Activity on a server without presence. `{host}` is replaced with the joined host. `null` = use `idle` |
| `default_presence.elapsed` | `true` | Add `timestamps.start` (time the state began) when the activity has none |
| `debug_log` | `false` | Verbose logs (view with DebugView, prefix `bedrock-presence:`) |
| `send_packet_class` | `BatchedNetworkPeer` | RTTI class whose vtable holds `sendPacket` |
| `send_packet_vtable_index` | `1` | `sendPacket` slot in that vtable |
| `send_packet_signature` | `""` | Byte pattern for `sendPacket` if the RTTI lookup fails |

Get the pin of a PEM certificate with:

```sh
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

Example:

```json
"default_presence": {
  "client_id": "123456789012345678",
  "elapsed": true,
  "idle": {"details": "In the menus", "assets": {"large_image": "minecraft"}},
  "server": {"details": "Playing on {host}", "assets": {"large_image": "minecraft"}}
}
```

## Protocol (newline-delimited JSON, UTF-8, max 16 KiB per line)

Full server-side guide (mapping, proxies, security, custom implementations): [docs/SERVER.md](docs/SERVER.md).

Client to server, right after connecting:
```json
{"type":"hello","version":1,"host":"play.example.org","game_port":19132,"transport":"raknet","client_random_id":"-4223170612291547000","self_signed_id":"6a4e0c0e-...","xuid":"2535412345678901","uuid":"8f4e...","username":"Steve"}
```
- `host` is the name the player joined, so a proxy can route on it.
- `transport` is `raknet` or `nethernet`.
- `client_random_id` and `self_signed_id` come from the client's Login packet; the server sees the same values in the player's login data, so it can map the link to the player.
  - Over NetherNet the Login packet is encrypted, so only `client_random_id` is sent, read from the game's `clientId.txt`.
  - `xuid`, `uuid` and `username` come from the Login identity: the chain's `extraData` (`XUID`, `identity`, `displayName`), or the newer token's `xid`/`xname` with `uuid` = `UUID.nameUUIDFromBytes(xid)`, as PNX/cloudburst derive it. RakNet only (NetherNet's Login is encrypted).
  - Any of these fields may be missing. All are claimed by the client: trust them only once the link is matched to a real player.

Server to client:
```json
{"type":"activity","client_id":"123456789012345678","activity":{"details":"Playing on Troporia","state":"Lobby","timestamps":{"start":1760000000},"assets":{"large_image":"logo","large_text":"Troporia"},"buttons":[{"label":"Website","url":"https://example.org"}]}}
{"type":"clear"}
{"type":"token","token":"<up to 256 chars>"}
```
- `activity` is passed to Discord `SET_ACTIVITY` as-is; see Discord's activity object docs for the fields.
- `client_id` is optional when `default_client_id` is set. Changing it reconnects to Discord with the new application.

Client replies to `token`:
```json
{"type":"token_sent"}
{"type":"token_error","reason":"send hook unavailable"}
```
`token_sent` is sent once the player is in-world and the packet went out. The game server then receives:

```
DebugInfoPacket (id 155): uniqueEntityId = 0, data = {"presence_token":"<token>"}
```

## Example server
`examples/presence_server.py` (stdlib only): logs the hello, sends a token, then sends an activity every 15s.

```sh
python examples/presence_server.py --client-id 123456789012345678
python examples/presence_server.py --client-id ... --tls-cert cert.pem --tls-key key.pem
```

## PowerNukkitX plugin
`examples/pnx-plugin` is a ready-made server side (Java 25, `./gradlew build`, jar in `build/libs`):
- Listens on 9514 (`config.yml`: port, bind address, optional TLS via PKCS#12 keystore).
- Hardened against fake clients: field validation, `max-connections` / `max-connections-per-ip`, message rate limit, `unlinked-timeout`, live links only replaced from the same IP, `require-same-ip` on by default (turn off behind IP-hiding proxies). See [docs/SERVER.md](docs/SERVER.md#security-checklist).
- Links each connection to its player by the Login identity in `hello` (`SelfSignedId`, plus `ClientRandomId`; `ClientRandomId` alone when a proxy blanks `SelfSignedId`).
- Also gives each connection a random token and links it when the token arrives through the game connection (works only when the DLL's sendPacket hook is available).
- Unlinked connections stay open and get a server-wide activity (server, player count). PNX's codec doesn't register DebugInfoPacket, so the token arrives as an `UnknownPacket` with id 155 through `PacketReceiveEvent`; the plugin decodes it and cancels the event.
- Unknown, used or expired (`token-timeout`) tokens are rejected. `require-same-ip` additionally checks that the TCP and game connections come from the same IP (disable behind proxies that hide player IPs).
- Example activity: "Playing on <host>", "In <world>", party size online/max, elapsed time; refreshed every `update-interval` seconds and on world change.
- API for other plugins:

```java
PresenceManager presence = PresencePlugin.manager();
presence.onLink(player -> { /* linked; push your own activity */ });
presence.setActivity(player, activityJson); // Discord activity object (Gson JsonObject)
presence.clear(player);
presence.connection(player).host();        // host the player joined
```

TLS keystore from a PEM cert/key:

```sh
openssl pkcs12 -export -in cert.pem -inkey key.pem -out plugins/BedrockPresence/presence.p12 -passout pass:changeit
```

## Notes
- **NetherNet** support is based on the server side (PNX-NetherNet / kastle NetherNet). If the client's join request is not plain HTTP, the hostname falls back to DNS. Check `debug_log` output after the update.
- **Token relay** needs RTTI for `BatchedNetworkPeer` in the game binary, or `send_packet_signature`. The lookup retries for 2 minutes. On failure the log lists every RTTI class with `NetworkPeer` in its name; pick one with `send_packet_class`. On success it logs `... vtable at ...`, and `debug_log` prints the first packet ids seen, which should be real packet ids (e.g. 144 PlayerAuthInput) if the slot is right.
- **Toolchain.** clang-cl/MSVC or the zig cross-build both work. The packet hook spells out the game's MSVC `std::string` layout itself, so the DLL's own standard library doesn't matter.

## Build from source
Requirements: Visual Studio with the "C++ Clang tools for Windows" component and Windows SDK, CMake 4.3+, Ninja, and Git.

From Developer PowerShell for VS:

```powershell
cmake --preset relwithdebinfo
cmake --build --preset relwithdebinfo
```

Outputs land in `build\relwithdebinfo\`.

Cross-build from Linux/macOS with [zig](https://ziglang.org) (mingw target, output in `dist/`):

```sh
tools/build_zig.sh                          # zig on PATH
ZIG="python -m ziglang" tools/build_zig.sh  # zig from pip install ziglang
```
