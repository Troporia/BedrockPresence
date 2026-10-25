package net.troporia.presence;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import io.netty.buffer.ByteBuf;
import org.cloudburstmc.protocol.bedrock.packet.BedrockPacket;
import org.cloudburstmc.protocol.bedrock.packet.DebugInfoPacket;
import org.cloudburstmc.protocol.bedrock.packet.UnknownPacket;
import org.powernukkitx.Player;
import org.powernukkitx.Server;
import org.powernukkitx.event.EventHandler;
import org.powernukkitx.event.Listener;
import org.powernukkitx.event.entity.EntityLevelChangeEvent;
import org.powernukkitx.event.player.PlayerJoinEvent;
import org.powernukkitx.event.player.PlayerQuitEvent;
import org.powernukkitx.event.server.PacketReceiveEvent;

import java.nio.charset.StandardCharsets;

/** Receives relayed presence tokens and keeps links in sync with players. */
final class PresenceListener implements Listener {

    /** DebugInfoPacket id; not registered in every codec, then it arrives as UnknownPacket. */
    private static final int DEBUG_INFO_PACKET = 155;
    private static final int MAX_DATA = 4096;

    private final PresencePlugin plugin;
    private final PresenceManager manager;

    PresenceListener(PresencePlugin plugin, PresenceManager manager) {
        this.plugin = plugin;
        this.manager = manager;
    }

    // Runs on the network thread for packets without a PNX handler.
    @EventHandler
    public void onPacket(PacketReceiveEvent event) {
        String data = debugInfoData(event.getPacket());
        if (data == null || !data.contains("presence_token")) {
            return;
        }
        event.setCancelled(true);
        Player player = event.getPlayer();
        if (player == null) {
            return;
        }
        String token;
        try {
            JsonObject json = JsonParser.parseString(data).getAsJsonObject();
            token = json.get("presence_token").getAsString();
        } catch (JsonParseException | IllegalStateException | NullPointerException | UnsupportedOperationException e) {
            return;
        }
        if (manager.link(token, player)) {
            Server.getInstance().getScheduler().scheduleTask(plugin, () -> {
                if (player.isOnline()) {
                    manager.fireLinked(player);
                }
            });
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (manager.linkByIdentity(player)) {
            manager.fireLinked(player);
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        manager.unlink(event.getPlayer());
    }

    @EventHandler
    public void onLevelChange(EntityLevelChangeEvent event) {
        if (event.getEntity() instanceof Player player && manager.isLinked(player)) {
            // The player is moved after the event; refresh on the next tick.
            Server.getInstance().getScheduler().scheduleTask(plugin, () -> plugin.updateActivity(player));
        }
    }

    private static String debugInfoData(BedrockPacket packet) {
        if (packet instanceof DebugInfoPacket debug) {
            return debug.getData();
        }
        if (packet instanceof UnknownPacket unknown && unknown.getPacketId() == DEBUG_INFO_PACKET
                && unknown.getPayload() != null) {
            return decodeDebugInfo(unknown.getPayload().duplicate());
        }
        return null;
    }

    /** DebugInfoPacket body: zigzag VarLong uniqueEntityId, VarUInt-length UTF-8 string. */
    private static String decodeDebugInfo(ByteBuf buf) {
        if (readVarLong(buf) < 0) {
            return null;
        }
        long len = readVarLong(buf);
        if (len < 0 || len > MAX_DATA || len > buf.readableBytes()) {
            return null;
        }
        return buf.readCharSequence((int) len, StandardCharsets.UTF_8).toString();
    }

    /** Unsigned VarInt up to 64 bits, -1 when malformed. */
    private static long readVarLong(ByteBuf buf) {
        long value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            if (!buf.isReadable()) {
                return -1;
            }
            byte b = buf.readByte();
            value |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return value & Long.MAX_VALUE;
            }
        }
        return -1;
    }
}
