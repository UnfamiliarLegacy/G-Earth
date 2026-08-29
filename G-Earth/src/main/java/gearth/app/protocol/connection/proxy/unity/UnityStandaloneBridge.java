package gearth.app.protocol.connection.proxy.unity;

import gearth.app.protocol.HConnection;
import gearth.protocol.HMessage;
import gearth.protocol.connection.HClient;
import gearth.app.protocol.connection.HProxy;
import gearth.app.protocol.connection.HProxySetter;
import gearth.app.protocol.connection.HState;
import gearth.app.protocol.connection.HStateSetter;
import gearth.app.protocol.connection.proxy.ProxyProvider;
import gearth.app.protocol.connection.proxy.http.WebSession;
import gearth.app.protocol.packethandler.unity.UnityPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

class UnityStandaloneBridge {

    private static final Logger LOG = LoggerFactory.getLogger(UnityStandaloneBridge.class);

    static final int PREFERRED_PORT = 9399;
    private static final long VERDICT_TIMEOUT_MS = 1500;
    private static final int MAX_REVISION_LENGTH = 512;
    private static final int MAX_PACKET_LENGTH = 0x200000;
    private static final byte HANDSHAKE_MARKER = (byte) 0xFF;

    // notify means the agent only lets extensions read the packet
    // intercept means the client waits until we answer if it stays or gets changed
    private static final byte FRAME_NOTIFY = 0x00;
    private static final byte FRAME_INTERCEPT = 0x01;
    private static final byte DIR_TO_SERVER = 0x01;

    private final HProxySetter proxySetter;
    private final HStateSetter stateSetter;
    private final HConnection hConnection;
    private final ProxyProvider proxyProvider;

    private ServerSocket serverSocket;
    private volatile Socket clientSocket;
    private volatile int port = -1;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final String cookie = newcookie();

    UnityStandaloneBridge(HProxySetter proxySetter, HStateSetter stateSetter,
                          HConnection hConnection, ProxyProvider proxyProvider) {
        this.proxySetter = proxySetter;
        this.stateSetter = stateSetter;
        this.hConnection = hConnection;
        this.proxyProvider = proxyProvider;
    }

    boolean start() {
        try {
            serverSocket = openServerSocket();
            port = serverSocket.getLocalPort();
            running.set(true);
            Thread t = new Thread(this::acceptLoop, "unity-standalone-accept");
            t.setDaemon(true);
            t.start();
            return true;
        } catch (IOException e) {
            LOG.error("Failed to start standalone bridge", e);
            return false;
        }
    }

    private static ServerSocket openServerSocket() throws IOException {
        try {
            return new ServerSocket(PREFERRED_PORT, 1, InetAddress.getLoopbackAddress());
        } catch (IOException portTaken) {
            return new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        }
    }

    int getPort() {
        return port;
    }

    String cookie() {
        return cookie;
    }

    private static String newcookie() {
        byte[] raw = new byte[16];
        new SecureRandom().nextBytes(raw);
        StringBuilder text = new StringBuilder();
        for (byte b : raw) text.append(String.format("%02x", b));
        return text.toString();
    }

    void stop() {
        running.set(false);
        try {
            if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
        } catch (IOException ignored) {
        }
        try {
            if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close();
        } catch (IOException ignored) {
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket sock = serverSocket.accept();
                if (!running.get()) {
                    sock.close();
                    return;
                }
                if (clientSocket != null && !clientSocket.isClosed()) {
                    LOG.warn("Refusing second standalone client, one is already connected");
                    sock.close();
                    continue;
                }
                clientSocket = sock;
                Thread t = new Thread(() -> handleClient(sock), "unity-standalone-session");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running.get()) LOG.warn("Standalone bridge accept error: {}", e.getMessage());
            }
        }
    }

    private void handleClient(Socket sock) {
        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(sock.getInputStream()));
            OutputStream rawOut = sock.getOutputStream();

            byte marker = in.readByte();
            if (marker != HANDSHAKE_MARKER) {
                LOG.warn("Standalone bridge: unexpected handshake byte 0x{}", Integer.toHexString(marker & 0xFF));
                sock.close();
                return;
            }

            int cookieLen = in.readInt();
            if (cookieLen <= 0 || cookieLen > 128) {
                sock.close();
                return;
            }
            byte[] cookieBytes = new byte[cookieLen];
            in.readFully(cookieBytes);
            if (!cookie.equals(new String(cookieBytes, StandardCharsets.UTF_8))) {
                LOG.warn("rejected wrong cookie");
                sock.close();
                return;
            }

            int revLen = in.readInt();
            if (revLen <= 0 || revLen > MAX_REVISION_LENGTH) {
                sock.close();
                return;
            }
            byte[] revBytes = new byte[revLen];
            in.readFully(revBytes);
            String revision = new String(revBytes, StandardCharsets.UTF_8);

            int hostLen = in.readInt();
            String host = "";
            if (hostLen > 0 && hostLen <= 256) {
                byte[] hostBytes = new byte[hostLen];
                in.readFully(hostBytes);
                host = new String(hostBytes, StandardCharsets.UTF_8);
            }
            LOG.info("Standalone client connected, revision {} host {}", revision, host);

            TcpSession session = new TcpSession(rawOut);

            UnityPacketHandler inHandler = new UnityPacketHandler(
                    hConnection.getExtensionHandler(),
                    hConnection.getTrafficObservables(),
                    session,
                    HMessage.Direction.TOCLIENT);

            UnityPacketHandler outHandler = new UnityPacketHandler(
                    hConnection.getExtensionHandler(),
                    hConnection.getTrafficObservables(),
                    session,
                    HMessage.Direction.TOSERVER);

            HProxy proxy = new HProxy(HClient.UNITY, host, host, -1, -1, "");
            proxy.verifyProxy(inHandler, outHandler, revision, "standalone");
            proxySetter.setProxy(proxy);
            stateSetter.setState(HState.CONNECTED);

            while (running.get() && !sock.isClosed()) {
                byte type = in.readByte();
                byte dir = in.readByte();
                int pktLen = in.readInt();
                if (pktLen < 0 || pktLen > MAX_PACKET_LENGTH) break;

                byte[] pkt = new byte[pktLen];
                if (pktLen > 0) in.readFully(pkt);

                UnityPacketHandler handler = (dir == DIR_TO_SERVER) ? outHandler : inHandler;
                if (type == FRAME_INTERCEPT) {
                    UnityPacketHandler.Verdict verdict = handler.interceptSync(pkt, VERDICT_TIMEOUT_MS);
                    session.sendVerdict(verdict.blocked, verdict.bytes);
                } else if (type == FRAME_NOTIFY) {
                    handler.reportOnly(pkt);
                }
            }
        } catch (EOFException | java.net.SocketException e) {
            LOG.info("Standalone client disconnected: {}", e.getMessage());
        } catch (IOException e) {
            if (running.get()) LOG.warn("Standalone session error: {}", e.getMessage());
        } finally {
            try {
                sock.close();
            } catch (IOException ignored) {
            }
            if (running.get()) proxyProvider.abort();
        }
    }

    private static class TcpSession implements WebSession {

        // what we send back to the agent
        // verdict is our answer to an intercept and inject pushes a new packet into the client
        private static final byte TAG_VERDICT = 0x10;
        private static final byte TAG_INJECT = 0x20;

        private final DataOutputStream out;

        TcpSession(OutputStream rawOut) {
            this.out = new DataOutputStream(new BufferedOutputStream(rawOut));
        }

        @Override
        public synchronized boolean send(byte[] data) throws IOException {
            if (data == null || data.length < 1) return false;
            out.writeByte(TAG_INJECT);
            out.writeInt(data.length);
            out.write(data);
            out.flush();
            return true;
        }

        synchronized void sendVerdict(boolean blocked, byte[] bytes) throws IOException {
            int payloadLen = 1 + (bytes == null ? 0 : bytes.length);
            out.writeByte(TAG_VERDICT);
            out.writeInt(payloadLen);
            out.writeByte(blocked ? 1 : 0);
            if (bytes != null && bytes.length > 0) out.write(bytes);
            out.flush();
        }
    }
}
