package net.troporia.presence;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** One BedrockPresence client: a TCP connection waiting for, or linked to, a player. */
public final class PresenceConnection {

    private final Socket socket;
    private final OutputStream out;
    private final String token;
    private final long createdAt = System.currentTimeMillis();

    // From the client's hello.
    private volatile String host = "";
    private volatile int gamePort;
    private volatile String transport = "";
    private volatile Long clientRandomId;
    private volatile UUID selfSignedId;
    private volatile String xuid = "";
    private volatile UUID uuid;
    private volatile String username = "";

    private volatile UUID player;
    private volatile long linkedAt;

    PresenceConnection(Socket socket, String token) throws IOException {
        this.socket = socket;
        this.out = socket.getOutputStream();
        this.token = token;
    }

    /** Send one JSON message (one line). Returns false if the connection is gone. */
    public synchronized boolean send(JsonObject message) {
        try {
            out.write((message + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            return true;
        } catch (IOException e) {
            close();
            return false;
        }
    }

    public boolean isClosed() {
        return socket.isClosed();
    }

    public void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    /**
     * Everything in the hello is claimed by the client. Values are only kept when they have
     * the expected shape, so nothing odd reaches logs, activities or lookups.
     */
    void hello(JsonObject hello) {
        String h = str(hello, "host");
        host = h.length() <= 253 && h.matches("[A-Za-z0-9.:\\[\\]-]*") ? h : "";
        try {
            int port = Integer.parseInt(str(hello, "game_port"));
            gamePort = port > 0 && port < 65536 ? port : 0;
        } catch (NumberFormatException e) {
            gamePort = 0;
        }
        String t = str(hello, "transport");
        transport = t.equals("raknet") || t.equals("nethernet") ? t : "";
        try {
            String id = str(hello, "client_random_id");
            clientRandomId = id.isEmpty() ? null : Long.parseLong(id);
        } catch (NumberFormatException e) {
            clientRandomId = null;
        }
        String x = str(hello, "xuid");
        xuid = x.length() <= 20 && x.matches("[0-9]*") ? x : "";
        String name = str(hello, "username");
        // Gamertags: letters, digits, spaces, up to 16 (+ "#1234" suffix for new ones).
        username = name.length() <= 21 && name.matches("[A-Za-z0-9 #_]*") ? name : "";
        uuid = parseUuid(str(hello, "uuid"));
        selfSignedId = parseUuid(str(hello, "self_signed_id"));
    }

    private static UUID parseUuid(String s) {
        if (s.length() != 36) {
            return null;
        }
        try {
            return UUID.fromString(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : "";
    }

    /**
     * XUID the client claims (from its Login packet; empty over NetherNet). Claimed by
     * the client, so trust it only after the link matched a real player.
     */
    public String xuid() {
        return xuid;
    }

    /** Player UUID the client claims (from its Login packet), or null. */
    public UUID uuid() {
        return uuid;
    }

    /** Gamertag the client claims (from its Login packet; empty over NetherNet). */
    public String username() {
        return username;
    }

    /** ClientRandomId from the client's Login packet, or null. */
    public Long clientRandomId() {
        return clientRandomId;
    }

    /** SelfSignedId from the client's Login packet, or null. */
    public UUID selfSignedId() {
        return selfSignedId;
    }

    void linked(UUID player) {
        this.player = player;
        this.linkedAt = System.currentTimeMillis();
    }

    Socket socket() {
        return socket;
    }

    String token() {
        return token;
    }

    long createdAt() {
        return createdAt;
    }

    /** Host the player joined (e.g. "play.example.org"); routes proxies / subdomains. */
    public String host() {
        return host;
    }

    public int gamePort() {
        return gamePort;
    }

    /** "raknet" or "nethernet". */
    public String transport() {
        return transport;
    }

    /** Linked player, or null while the token has not arrived yet. */
    public UUID player() {
        return player;
    }

    /** Epoch millis when the player was linked. */
    public long linkedAt() {
        return linkedAt;
    }

    public String remote() {
        return String.valueOf(socket.getRemoteSocketAddress());
    }
}
