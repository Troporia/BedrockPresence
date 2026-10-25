package net.troporia.presence;

import com.google.gson.JsonObject;
import org.powernukkitx.Player;
import org.powernukkitx.Server;
import org.powernukkitx.network.process.auth.ClientChainData;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.powernukkitx.utils.Logger;

/**
 * Maps presence TCP connections to players, two ways:
 * <ul>
 *   <li>identity: the client's hello carries ClientRandomId/SelfSignedId from its
 *   Login packet, matched against {@link Player#getClientChainData()};</li>
 *   <li>token: the connection gets a random token, the client relays it through its
 *   game connection (DebugInfoPacket) and {@link #link(String, Player)} pairs them.</li>
 * </ul>
 * Unlinked connections stay open (they get a server-wide activity). Thread-safe.
 */
public final class PresenceManager {

    private final Map<String, PresenceConnection> pending = new ConcurrentHashMap<>();
    private final Map<UUID, PresenceConnection> linked = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Consumer<Player>> linkListeners = new CopyOnWriteArrayList<>();
    private final Map<String, PresenceConnection> unlinked = new ConcurrentHashMap<>(); // by token
    private final String clientId;
    private final long tokenTimeoutMs;
    private final boolean requireSameIp;
    private final Logger log;

    PresenceManager(String clientId, long tokenTimeoutMs, boolean requireSameIp, Logger log) {
        this.clientId = clientId;
        this.tokenTimeoutMs = tokenTimeoutMs;
        this.requireSameIp = requireSameIp;
        this.log = log;
    }

    // --- API -------------------------------------------------------------------

    /** Called (on the main thread) whenever a player gets linked. */
    public void onLink(Consumer<Player> listener) {
        linkListeners.add(listener);
    }

    public boolean isLinked(Player player) {
        return linked.containsKey(player.getUniqueId());
    }

    /** The player's presence connection, or null when not linked. */
    public PresenceConnection connection(Player player) {
        return linked.get(player.getUniqueId());
    }

    /**
     * Show a Discord activity for the player. {@code activity} is a Discord activity
     * object (details, state, timestamps, assets, party, buttons...).
     */
    public boolean setActivity(Player player, JsonObject activity) {
        PresenceConnection c = linked.get(player.getUniqueId());
        return c != null && setActivity(c, activity);
    }

    /** Activity for a single connection, linked or not. */
    public boolean setActivity(PresenceConnection c, JsonObject activity) {
        JsonObject msg = new JsonObject();
        msg.addProperty("type", "activity");
        if (!clientId.isEmpty()) {
            msg.addProperty("client_id", clientId);
        }
        msg.add("activity", activity);
        return c.send(msg);
    }

    /** Connections not linked to a player yet. */
    public Iterable<PresenceConnection> unlinkedConnections() {
        return unlinked.values();
    }

    public boolean clear(Player player) {
        PresenceConnection c = linked.get(player.getUniqueId());
        if (c == null) {
            return false;
        }
        JsonObject msg = new JsonObject();
        msg.addProperty("type", "clear");
        return c.send(msg);
    }

    // --- internals -------------------------------------------------------------

    void addPending(PresenceConnection c) {
        pending.put(c.token(), c);
        unlinked.put(c.token(), c);
    }

    /** Link c to an online player with the same Login identity, if any. Main thread. */
    Player linkByIdentity(PresenceConnection c) {
        if (c.player() != null) {
            return null;
        }
        for (Player p : Server.getInstance().getOnlinePlayers().values()) {
            if (identityMatches(c, p) && linkConnection(c, p, "identity")) {
                return p;
            }
        }
        return null;
    }

    /** A player joined: link the unlinked connection with their Login identity. Main thread. */
    boolean linkByIdentity(Player player) {
        if (linked.containsKey(player.getUniqueId())) {
            return false;
        }
        for (PresenceConnection c : unlinked.values()) {
            if (identityMatches(c, player) && linkConnection(c, player, "identity")) {
                return true;
            }
        }
        return false;
    }

    /** Pair the connection holding token with player. False for unknown/expired tokens. */
    boolean link(String token, Player player) {
        PresenceConnection c = pending.remove(token);
        if (c == null) {
            // Players can send any DebugInfoPacket; don't let them flood the log.
            log.debug("unknown or used presence token from " + player.getName());
            return false;
        }
        if (System.currentTimeMillis() - c.createdAt() > tokenTimeoutMs) {
            log.debug("expired presence token from " + player.getName());
            return false;
        }
        return linkConnection(c, player, "token");
    }

    private boolean linkConnection(PresenceConnection c, Player player, String how) {
        if (requireSameIp && !sameIp(c, player)) {
            log.warning("presence link for " + player.getName() + " came from a different IP ("
                    + c.remote() + ")");
            return false;
        }
        // A live link is only replaced from the same address (the client reconnecting),
        // so a second connection with copied claims cannot take over someone's presence.
        PresenceConnection current = linked.get(player.getUniqueId());
        if (current != null && current != c && !current.isClosed() && !sameAddress(current, c)) {
            log.warning("presence link for " + player.getName() + " refused: already linked from "
                    + current.remote() + ", new connection from " + c.remote());
            return false;
        }
        pending.remove(c.token(), c);
        unlinked.remove(c.token(), c);
        c.linked(player.getUniqueId());
        PresenceConnection old = linked.put(player.getUniqueId(), c);
        if (old != null && old != c) {
            old.close();
        }
        log.info("presence linked by " + how + ": " + player.getName() + " <-> " + c.remote() + " (host "
                + c.host() + ", " + c.transport() + ", claims " + c.username() + " xuid " + c.xuid()
                + " uuid " + c.uuid() + ")");
        return true;
    }

    /**
     * Same Login identity: SelfSignedId (and ClientRandomId when sent) when the server
     * has a real SelfSignedId, else ClientRandomId alone (proxies may blank SelfSignedId).
     */
    private static boolean identityMatches(PresenceConnection c, Player player) {
        ClientChainData d = player.getClientChainData();
        if (d == null) {
            return false;
        }
        Long randomId = c.clientRandomId();
        UUID selfSigned = d.getSelfSignedId();
        boolean selfSignedUsable = c.selfSignedId() != null && selfSigned != null
                && (selfSigned.getMostSignificantBits() | selfSigned.getLeastSignificantBits()) != 0;
        if (selfSignedUsable) {
            return selfSigned.equals(c.selfSignedId())
                    && (randomId == null || randomId == d.getClientRandomId());
        }
        return randomId != null && randomId == d.getClientRandomId();
    }

    void fireLinked(Player player) {
        for (Consumer<Player> l : linkListeners) {
            try {
                l.accept(player);
            } catch (RuntimeException e) {
                log.warning("presence link listener failed: " + e);
            }
        }
    }

    void unlink(Player player) {
        PresenceConnection c = linked.remove(player.getUniqueId());
        if (c != null) {
            c.close();
        }
    }

    /** Connection closed by the client. */
    void removed(PresenceConnection c) {
        pending.remove(c.token(), c);
        unlinked.remove(c.token(), c);
        UUID player = c.player();
        if (player != null) {
            linked.remove(player, c);
        }
    }

    /** Invalidate tokens that were not relayed in time (the connection stays open). */
    void expirePending() {
        long now = System.currentTimeMillis();
        pending.values().removeIf(c -> now - c.createdAt() > tokenTimeoutMs);
    }

    /**
     * Close unlinked connections older than timeoutMs, unless a player from the same
     * address is online (identity linking may be impossible, e.g. some NetherNet setups,
     * and such a client still gets the server-wide activity). Main thread.
     */
    void expireUnlinked(long timeoutMs) {
        long now = System.currentTimeMillis();
        for (PresenceConnection c : unlinked.values()) {
            if (now - c.createdAt() <= timeoutMs) {
                continue;
            }
            boolean playerOnline = false;
            for (Player p : Server.getInstance().getOnlinePlayers().values()) {
                if (sameIp(c, p)) {
                    playerOnline = true;
                    break;
                }
            }
            if (!playerOnline) {
                c.close();
                removed(c);
            }
        }
    }

    void closeAll() {
        unlinked.values().forEach(PresenceConnection::close);
        linked.values().forEach(PresenceConnection::close);
        pending.clear();
        unlinked.clear();
        linked.clear();
    }

    private static boolean sameAddress(PresenceConnection a, PresenceConnection b) {
        InetAddress x = a.socket().getInetAddress();
        return x != null && x.equals(b.socket().getInetAddress());
    }

    private static boolean sameIp(PresenceConnection c, Player player) {
        InetSocketAddress game = player.getSocketAddress();
        InetAddress tcp = c.socket().getInetAddress();
        return game != null && tcp != null && tcp.equals(game.getAddress());
    }
}
