# BedrockPresence server side

What a server, proxy or standalone service needs to implement so BedrockPresence
clients show its Discord activity. `examples/pnx-plugin` (PowerNukkitX) and
`examples/presence_server.py` are reference implementations; this document is
the contract they follow.

## Overview

```
Minecraft client (DLL injected)               your infrastructure
 ├─ game connection ────────────────────────▶ game server / proxy (19132)
 └─ presence link (TCP, JSON lines) ────────▶ presence service (9514)
                                                └─ maps link ⇄ player, sends activities
```

1. The client joins `play.example.org:19132` as usual.
2. Once the server answers (RakNet handshake or NetherNet DTLS), the DLL opens
   TCP to `play.example.org:9514`. It resolves the **hostname the player typed**
   itself, so DNS can point the presence name somewhere other than the game.
3. The DLL sends `hello`. Your service replies with `activity` messages.
4. When the game disconnects for any reason, the DLL closes the link at once.
   You never need to time out a client that left; just handle the socket closing.

Nothing in the game protocol changes. A server without a presence service is
unaffected: the client retries every 30 s and shows its local default presence.

## Where the client connects

The client connects to `<joined host>:9514` (the port is the client's `port`
setting), over RakNet and NetherNet alike.

`<joined host>` comes from the RakNet Login `ServerAddress`, the NetherNet
`Host:` header, the game's DNS lookup, or the raw IP, in that order. It is the
name the player typed, so several subdomains on one IP (`play.` / `test.`)
are told apart in `hello.host`.

## Wire format

- TCP. Optional TLS: the client speaks TLS 1.2 (Windows SChannel). With
  `tls_verify` the certificate must chain to the Windows trust store and match
  the hostname; with `tls_pin_sha256` a self-signed certificate works.
- UTF-8 JSON objects, one per line (`\n`, a trailing `\r` is ignored).
- Lines over 16 KiB: the client drops the connection. Enforce your own limit too.
- Unknown `type`s and unknown fields must be ignored by both sides.

### Client → server

`hello`, always the first line, sent immediately after connecting:

```json
{"type":"hello","version":1,"host":"play.example.org","game_port":19132,
 "transport":"raknet","client_random_id":"-4223170612291547000",
 "self_signed_id":"6a4e0c0e-0000-4000-8000-000000000000",
 "xuid":"2535412345678901","uuid":"8f4e0000-0000-3000-8000-000000000000",
 "username":"Steve"}
```

| Field | Type | Notes |
|---|---|---|
| `version` | int | Protocol version, currently 1 |
| `host` | string | Name (or IP) the player joined, without port |
| `game_port` | int | Game port the player joined |
| `transport` | string | `raknet` or `nethernet` |
| `client_random_id` | string | int64 as decimal text. Login `ClientRandomId` (RakNet), or the game's `clientId.txt` (NetherNet) |
| `self_signed_id` | string | Login `SelfSignedId` UUID. RakNet only |
| `xuid`, `uuid`, `username` | string | Login identity. RakNet only. `uuid` = `UUID.nameUUIDFromBytes(xuid)` for token logins |

Every field after `transport` may be missing. **All of them are claims made by
the client** (see Security).

Replies to `token` (only if you use the token relay):

```json
{"type":"token_sent"}
{"type":"token_error","reason":"send hook unavailable"}
```

### Server → client

```json
{"type":"activity","client_id":"123456789012345678","activity":{...}}
{"type":"clear"}
{"type":"token","token":"<1-256 chars>"}
```

- `activity`: passed to Discord `SET_ACTIVITY` unchanged, so every field
  Discord supports works (table below). Discord drops the **whole** activity
  if one field is invalid, so validate before sending.
- `client_id`: Discord application id. Optional if the user configured
  `default_client_id`. Changing it makes the client reconnect to Discord.
- `clear`: drops your activity; the client goes back to its local default
  presence (if the user configured one).
- Send `activity` again whenever something changes. There is no partial
  update. Discord rate-limits to about 5 updates per 20 s per client, so don't
  send faster than every ~4 s.

### Activity fields

| Field | Type | Shown as |
|---|---|---|
| `type` | int | 0 Playing, 2 Listening, 3 Watching, 5 Competing (1/4 not allowed for apps) |
| `status_display_type` | int | Member-list text: 0 app name, 1 `state`, 2 `details` |
| `details` | string 2–128 | First line |
| `details_url` | https url | Makes `details` a link |
| `state` | string 2–128 | Second line |
| `state_url` | https url | Makes `state` a link |
| `timestamps.start` / `.end` | epoch seconds | "elapsed" / countdown |
| `assets.large_image` | asset key or https url | Big picture |
| `assets.large_text` | string ≤128 | Big picture tooltip |
| `assets.large_url` | https url | Big picture link |
| `assets.small_image` / `small_text` / `small_url` | as above | Small badge |
| `party.id` | string ≤128 | Groups players |
| `party.size` | `[current, max]` | "2 of 4" |
| `instance` | bool | Activity is an instanced game session |
| `buttons` | ≤2 × `{label ≤32, url https}` | Link buttons (only other users see them) |

- The **title** is the Discord application's name. Use a different
  `client_id` (another app in the Developer Portal) to change it.
- Asset keys must be uploaded to that application (Rich Presence → Art
  Assets). Images can also be direct `https://` URLs.
- `secrets` (join/spectate) are not supported: the DLL does not handle
  Discord's join events.
- `status_display_type`, `details_url`, `state_url` and the `*_url` asset
  links are newer Discord features; older Discord clients ignore them.

## Mapping a link to a player

The presence connection and the game connection are separate sockets. Two ways
to pair them:

### 1. Login identity (recommended, works today)

Compare `hello` with the login data your server already has for the player:

| hello | PowerNukkitX | WaterdogPE / cloudburst protocol |
|---|---|---|
| `self_signed_id` | `player.getClientChainData().getSelfSignedId()` | client data JWT `SelfSignedId` |
| `client_random_id` | `player.getClientChainData().getClientRandomId()` | client data JWT `ClientRandomId` |

Rules used by the PNX plugin:

- If the server knows a non-nil `SelfSignedId`: require `self_signed_id` to
  match, and `client_random_id` too when present.
- Else (a proxy blanked `SelfSignedId`, or NetherNet): match
  `client_random_id` alone.
- Never link on `xuid`, `uuid` or `username`. Those are public; anyone can
  claim them.

`ClientRandomId` and `SelfSignedId` are never shown to other players, so a
third party cannot easily guess them. They are not secret from the client's own
network path, though: use TLS where that matters.

Run the matching both when the `hello` arrives (the player may already be
online) and when a player joins (the link may arrive first).

### 2. Token relay (optional, currently unavailable on GDK builds)

Send `{"type":"token","token":"<random>"}` with ≥128 bits of randomness. The
client sends it to the game server inside a `DebugInfoPacket`:

```
DebugInfoPacket (id 155)
  uniqueEntityId  zigzag VarLong   (0)
  data            VarUInt length + UTF-8   {"presence_token":"<token>"}
```

Codecs that don't register id 155 deliver it as an unknown packet; decode it by
hand (see `PresenceListener.decodeDebugInfo`). Cancel or drop it afterwards.
Tokens are single-use and should expire (the plugin uses 60 s). On the current
game build the DLL cannot inject packets and answers `token_error`, so treat
this path as optional.

## Proxies

### WaterdogPE (or any Bedrock proxy)

The proxy sees every player's Login, so it is the natural place for the
presence service:

- Run the service in the proxy (plugin) on 9514 of the address players join.
  Map links with the Login identity of the proxied player. Forward activity
  updates from backends however you like (plugin messaging, Redis, ...).
- Or run it on a backend and point the presence hostname there with DNS (e.g.
  `play.example.org` → proxy for the game, presence goes to the same name, so
  forward TCP 9514 from the proxy host to the backend). The backend must then
  see the real `ClientRandomId`/`SelfSignedId`. WaterdogPE forwards the client
  data JWT, so it does.
- Behind a proxy that hides player IPs, the game connection comes from the
  proxy while the presence link comes from the player. Turn off any
  "same IP" check (`require-same-ip: false` in the PNX plugin) or make it
  compare against the forwarded address.
- Forced hosts: `hello.host` carries the name the player joined, so route the
  presence link the same way your proxy routes `ServerAddress`.

### TCP reverse proxies / load balancers

Plain TCP forwarding of 9514 works. If you terminate TLS at the proxy, the
client only needs the proxy's certificate to be valid for the joined host (or
pinned). Pass the client IP (PROXY protocol) if you check IPs.

## Security checklist

Everything on the presence port is reachable by anyone, not only by players
with the DLL. Assume hostile clients:

- **Never trust `hello`.** Link only by `self_signed_id`/`client_random_id`
  compared with server-side login data (or a token you issued). Don't use the
  claimed `xuid`/`uuid`/`username` for anything but display or logs after the
  link matched.
- **Validate field shapes** before logging or using them: host characters and
  length, UUID format, numeric ids. Cap line length (16 KiB) and use a hello
  timeout (10 s).
- **Don't let a second connection steal a live link.** Replace an existing link
  only when the new connection comes from the same address (a client
  reconnecting); otherwise refuse it.
- **Same-IP check** where the network allows it (no IP-hiding proxy): link only
  when the presence connection and the game connection share an IP.
- **Limits:** global connection cap, per-IP cap, per-connection message rate,
  and close unlinked connections after a while unless a player from that IP is
  online.
- **What you send is public.** Activities appear on the player's Discord
  profile. Don't put coordinates, IPs or anything private there unless the
  player opted in.
- **Tokens** (if used): ≥128 random bits, single-use, short expiry, and don't
  log a warning per bad token (players can send arbitrary `DebugInfoPacket`s).
- **TLS** if links cross untrusted networks. `hello` carries Login ids that
  could be replayed by someone sniffing the link when no same-IP check applies.

## Minimal implementation (pseudocode)

```
listen tcp :9514
on connect(sock):
    if over global/per-IP limit: close
    hello = read_line(timeout=10s, max=16KiB) as JSON
    if hello.type != "hello": close
    conn = validate(hello)              # shapes only, drop bad fields
    send(sock, {"type":"activity","activity": server_wide_activity()})
    try_link(conn)                      # compare ids with online players
    loop read_line(rate-limited): ignore / log token replies
    on close: unlink(conn)

on player_join(p):   try_link_any_unlinked(p)
on player_quit(p):   close linked connection (the client closes too)
on state change(p):  send(conn_of(p), {"type":"activity", ...})
```
