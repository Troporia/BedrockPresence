package net.troporia.presence;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.powernukkitx.utils.Logger;

/** TCP listener for BedrockPresence clients (newline-delimited JSON, optional TLS). */
final class PresenceServer {

    private static final int MAX_LINE = 16 * 1024;
    private static final int HELLO_TIMEOUT_MS = 10_000;
    /** Messages a client may send per RATE_WINDOW_MS; it has no reason to send more than a few. */
    private static final int MAX_MESSAGES = 20;
    private static final long RATE_WINDOW_MS = 10_000;

    private final PresenceManager manager;
    private final Logger log;
    private final java.util.function.Consumer<PresenceConnection> onHello;
    private final SecureRandom random = new SecureRandom();
    private final int maxConnections;
    private final int maxPerIp;
    private final AtomicInteger connections = new AtomicInteger();
    private final Map<InetAddress, AtomicInteger> perIp = new ConcurrentHashMap<>();
    private ServerSocket server;

    /** onHello runs on the connection's thread once the hello arrived. */
    PresenceServer(PresenceManager manager, Logger log, int maxConnections, int maxPerIp,
                   java.util.function.Consumer<PresenceConnection> onHello) {
        this.manager = manager;
        this.log = log;
        this.maxConnections = maxConnections;
        this.maxPerIp = maxPerIp;
        this.onHello = onHello;
    }

    void start(String bindAddress, int port, SSLContext tls) throws IOException {
        if (tls != null) {
            SSLServerSocket s = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket();
            // The client speaks TLS 1.2 (SChannel).
            s.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            server = s;
        } else {
            server = new ServerSocket();
        }
        server.bind(new InetSocketAddress(InetAddress.getByName(bindAddress), port));
        Thread.ofPlatform().name("presence-accept").daemon().start(this::acceptLoop);
        log.info("presence server listening on " + bindAddress + ":" + port + (tls != null ? " (TLS)" : ""));
    }

    void stop() {
        try {
            if (server != null) {
                server.close();
            }
        } catch (IOException ignored) {
        }
    }

    static SSLContext loadTls(File keystore, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(keystore)) {
            ks.load(in, password.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket socket = server.accept();
                InetAddress ip = socket.getInetAddress();
                if (!reserve(ip)) {
                    socket.close();
                    continue;
                }
                Thread.ofVirtual().name("presence-" + socket.getRemoteSocketAddress()).start(() -> {
                    try {
                        serve(socket);
                    } finally {
                        release(ip);
                    }
                });
            } catch (IOException e) {
                if (!server.isClosed()) {
                    log.warning("presence accept failed: " + e);
                }
            }
        }
    }

    /** Count a new connection; false when the global or per-IP limit is reached. */
    private boolean reserve(InetAddress ip) {
        if (connections.incrementAndGet() > maxConnections) {
            connections.decrementAndGet();
            return false;
        }
        AtomicInteger n = perIp.computeIfAbsent(ip, k -> new AtomicInteger());
        if (n.incrementAndGet() > maxPerIp) {
            release(ip);
            return false;
        }
        return true;
    }

    private void release(InetAddress ip) {
        connections.decrementAndGet();
        perIp.computeIfPresent(ip, (k, n) -> n.decrementAndGet() <= 0 ? null : n);
    }

    private void serve(Socket socket) {
        PresenceConnection c = null;
        try (socket) {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(HELLO_TIMEOUT_MS);
            Reader in = new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8);

            String first = readLine(in);
            if (first == null) {
                return;
            }
            JsonObject hello = JsonParser.parseString(first).getAsJsonObject();
            if (!"hello".equals(str(hello, "type"))) {
                return;
            }
            socket.setSoTimeout(0);

            c = new PresenceConnection(socket, newToken());
            c.hello(hello);
            manager.addPending(c);
            JsonObject token = new JsonObject();
            token.addProperty("type", "token");
            token.addProperty("token", c.token());
            c.send(token);
            onHello.accept(c);

            String line;
            long windowStart = System.currentTimeMillis();
            int messages = 0;
            while ((line = readLine(in)) != null) {
                long now = System.currentTimeMillis();
                if (now - windowStart > RATE_WINDOW_MS) {
                    windowStart = now;
                    messages = 0;
                }
                if (++messages > MAX_MESSAGES) {
                    log.warning("presence client " + c.remote() + " sends too much, closing");
                    return;
                }
                JsonObject msg = JsonParser.parseString(line).getAsJsonObject();
                switch (str(msg, "type")) {
                    case "token_sent" -> { /* the DebugInfoPacket is on its way */ }
                    case "token_error" -> log.debug("presence client " + c.remote()
                            + " cannot relay its token");
                    default -> { }
                }
            }
        } catch (SocketTimeoutException e) {
            // no hello in time
        } catch (IOException | RuntimeException e) {
            // connection dropped or garbage (bad JSON, wrong types); just close it
        } finally {
            if (c != null) {
                manager.removed(c);
            }
        }
    }

    private String newToken() {
        byte[] b = new byte[18];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() ? o.get(key).getAsString() : "";
    }

    /** Line without the newline, null at end of stream. Throws past MAX_LINE. */
    private static String readLine(Reader in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = in.read()) != -1) {
            if (ch == '\n') {
                if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == '\r') {
                    sb.setLength(sb.length() - 1);
                }
                return sb.toString();
            }
            if (sb.length() >= MAX_LINE) {
                throw new IOException("line too long");
            }
            sb.append((char) ch);
        }
        return sb.isEmpty() ? null : sb.toString();
    }
}
