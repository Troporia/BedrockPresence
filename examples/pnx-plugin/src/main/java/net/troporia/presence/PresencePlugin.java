package net.troporia.presence;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.powernukkitx.Player;
import org.powernukkitx.Server;
import org.powernukkitx.plugin.PluginBase;
import org.powernukkitx.utils.Config;
import org.powernukkitx.utils.TextFormat;

import javax.net.ssl.SSLContext;
import java.io.File;

/**
 * Server side of BedrockPresence. Accepts client DLL connections, links them to
 * players via the relayed token, and shows an example activity.
 *
 * Other plugins: {@code PresencePlugin.manager().setActivity(player, activity)}.
 */
public class PresencePlugin extends PluginBase {

    private static PresenceManager manager;
    private PresenceServer server;
    private String largeImage;

    /** Presence API, or null while the plugin is disabled. */
    public static PresenceManager manager() {
        return manager;
    }

    @Override
    public void onEnable() {
        saveDefaultConfig();
        Config cfg = getConfig();
        largeImage = cfg.getString("large-image", "logo");

        manager = new PresenceManager(cfg.getString("client-id", ""),
                cfg.getLong("token-timeout", 60) * 1000L, cfg.getBoolean("require-same-ip", true),
                getLogger());

        SSLContext tls = null;
        if (cfg.getBoolean("tls.enabled", false)) {
            File keystore = new File(getDataFolder(), cfg.getString("tls.keystore", "presence.p12"));
            try {
                tls = PresenceServer.loadTls(keystore, cfg.getString("tls.password", ""));
            } catch (Exception e) {
                getLogger().error("presence TLS disabled, cannot load " + keystore + ": " + e);
                setEnabled(false);
                return;
            }
        }

        server = new PresenceServer(manager, getLogger(), cfg.getInt("max-connections", 500),
                cfg.getInt("max-connections-per-ip", 4), c -> {
            // Show something right away, then link on the main thread (the player may
            // already be online when the link arrives late).
            manager.setActivity(c, serverActivity(c));
            getServer().getScheduler().scheduleTask(this, () -> {
                Player p = manager.linkByIdentity(c);
                if (p != null) {
                    manager.fireLinked(p);
                }
            });
        });
        try {
            server.start(cfg.getString("bind-address", "0.0.0.0"), cfg.getInt("port", 9514), tls);
        } catch (Exception e) {
            getLogger().error("cannot start presence server: " + e);
            setEnabled(false);
            return;
        }

        getServer().getPluginManager().registerEvents(new PresenceListener(this, manager), this);
        manager.onLink(this::updateActivity);

        int interval = Math.max(5, cfg.getInt("update-interval", 15)) * 20;
        long unlinkedTimeoutMs = Math.max(30, cfg.getLong("unlinked-timeout", 300)) * 1000L;
        getServer().getScheduler().scheduleRepeatingTask(this, () -> {
            manager.expirePending();
            manager.expireUnlinked(unlinkedTimeoutMs);
            for (Player p : Server.getInstance().getOnlinePlayers().values()) {
                if (manager.isLinked(p)) {
                    updateActivity(p);
                }
            }
            for (PresenceConnection c : manager.unlinkedConnections()) {
                manager.setActivity(c, serverActivity(c));
            }
        }, interval);
    }

    @Override
    public void onDisable() {
        if (server != null) {
            server.stop();
        }
        if (manager != null) {
            manager.closeAll();
        }
        manager = null;
    }

    /** Activity for a connection not linked to a player yet: server and player count. */
    JsonObject serverActivity(PresenceConnection c) {
        Server s = Server.getInstance();
        String name = TextFormat.clean(s.getMotd());
        JsonObject activity = new JsonObject();
        activity.addProperty("details", "Playing on " + (c.host().isEmpty() ? name : c.host()));
        activity.addProperty("state", s.getOnlinePlayers().size() + " online");
        JsonObject timestamps = new JsonObject();
        timestamps.addProperty("start", c.createdAt() / 1000);
        activity.add("timestamps", timestamps);
        JsonObject assets = new JsonObject();
        assets.addProperty("large_image", largeImage);
        assets.addProperty("large_text", name);
        activity.add("assets", assets);
        return activity;
    }

    /** Example activity: server name, current world, player count, time since link. */
    void updateActivity(Player player) {
        PresenceConnection c = manager.connection(player);
        if (c == null) {
            return;
        }
        Server s = Server.getInstance();
        String name = TextFormat.clean(s.getMotd());
        String host = c.host().isEmpty() ? name : c.host();

        JsonObject activity = new JsonObject();
        activity.addProperty("details", "BedrockPresence Test");
        activity.addProperty("state", "In " + player.getLevel().getName() + " at " + player.getPosition().getX() + ", " + player.getPosition().getY() + ", " + player.getPosition().getZ());

        JsonObject timestamps = new JsonObject();
        timestamps.addProperty("start", c.linkedAt() / 1000);
        activity.add("timestamps", timestamps);

        JsonObject assets = new JsonObject();
        assets.addProperty("Test", largeImage);
        activity.add("assets", assets);

        JsonObject party = new JsonObject();
        party.addProperty("id", host);
        JsonArray size = new JsonArray();
        size.add(s.getOnlinePlayers().size());
        size.add(s.getMaxPlayers());
        party.add("size", size);
        activity.add("party", party);

        manager.setActivity(player, activity);
    }
}
