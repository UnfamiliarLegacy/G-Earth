package gearth.app.protocol.connection.proxy.unity;

import gearth.app.protocol.HConnection;
import gearth.app.protocol.StateChangeListener;
import gearth.app.protocol.connection.HProxySetter;
import gearth.app.protocol.connection.HState;
import gearth.app.protocol.connection.HStateSetter;
import gearth.app.protocol.connection.proxy.ProxyProvider;
import gearth.app.protocol.connection.proxy.http.HttpProxyManager;
import gearth.app.services.unity_tools.GUnityFileServer;
import gearth.app.services.unity_tools.UnityStandaloneLauncher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

public class UnityProxyProvider implements ProxyProvider, StateChangeListener {

    private static final Logger LOG = LoggerFactory.getLogger(UnityProxyProvider.class);

    private final HStateSetter stateSetter;
    private final HConnection hConnection;
    private final UnityLaunchMode mode;
    private final UnityWebsocketServer websocketServer;
    private final HttpProxyManager httpProxy;
    private final UnityStandaloneBridge standaloneBridge;
    private final UnityStandaloneLauncher launcher;

    private volatile Process clientProcess;
    private volatile Thread shutdownHook;
    private final AtomicBoolean aborted;

    public UnityProxyProvider(HProxySetter proxySetter, HStateSetter stateSetter, HConnection hConnection, UnityLaunchMode mode) {
        this.stateSetter = stateSetter;
        this.hConnection = hConnection;
        this.mode = mode;
        this.websocketServer = new UnityWebsocketServer(new UnityCommunicatorConfig(proxySetter, stateSetter, hConnection, this));
        this.httpProxy = new HttpProxyManager();
        this.standaloneBridge = new UnityStandaloneBridge(proxySetter, stateSetter, hConnection, this);
        this.launcher = new UnityStandaloneLauncher();
        this.aborted = new AtomicBoolean(false);
    }

    @Override
    public void start() throws IOException {
        try {
            hConnection.getStateObservable().addListener(this);

            // standalone is windows only, there is no linux client. TODO macos
            boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
            if (mode == UnityLaunchMode.BUILD && windows) {
                startStandalone();
                return;
            }

            LOG.info("Starting Unity Websocket Server");

            if (!this.websocketServer.start()) {
                LOG.error("Failed to start unity websocket server");
                abort();
                return;
            }

            LOG.info("Unity websocket server started on port {}", this.websocketServer.getPort());

            LOG.info("Starting unity http proxy");

            if (!this.httpProxy.start(new GUnityFileServer(this.websocketServer.getPort()))) {
                LOG.error("Failed to start nitro proxy");
                abort();
                return;
            }

            LOG.info("Unity http proxy started");

            stateSetter.setState(HState.WAITING_FOR_CLIENT);
        } catch (Exception e) {
            LOG.error("Failed to start unity proxy", e);

            abort();
        }
    }

    private void startStandalone() {
        if (!standaloneBridge.start()) {
            LOG.error("Failed to start unity standalone bridge");
            abort();
            return;
        }

        int bridgePort = standaloneBridge.getPort();
        LOG.info("Unity standalone bridge listening on port {}", bridgePort);

        stateSetter.setState(HState.WAITING_FOR_CLIENT);

        Optional<Process> process = launcher.connect(bridgePort, standaloneBridge.cookie());
        if (process.isEmpty()) {
            LOG.error("Failed to start the Habbo Unity standalone client");
            abort();
            return;
        }

        clientProcess = process.get();
        clientProcess.onExit().thenRun(this::abort);

        shutdownHook = new Thread(() -> {
            Process p = clientProcess;
            if (p != null && p.isAlive()) p.destroyForcibly();
            launcher.release();
        }, "unity-standalone-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
    }

    @Override
    public synchronized void abort() {
        if (!aborted.compareAndSet(false, true)) return;

        stateSetter.setState(HState.ABORTING);

        new Thread(() -> {
            hConnection.getStateObservable().removeListener(this);

            if (mode == UnityLaunchMode.BUILD) {
                LOG.info("Stopping unity standalone bridge");
                standaloneBridge.stop();

                Process process = clientProcess;
                if (process != null && process.isAlive()) {
                    process.destroy();
                }

                launcher.release();

                Thread hook = shutdownHook;
                if (hook != null) {
                    try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException ignored) {}
                    shutdownHook = null;
                }

                stateSetter.setState(HState.NOT_CONNECTED);
                return;
            }

            LOG.info("Stopping unity websocket server");

            try {
                websocketServer.stop();
            } catch (Exception ex) {
                LOG.error("Failed to stop unity websocket server", ex);
            } finally {
                LOG.info("Unity websocket server stopped");
            }

            LOG.info("Stopping unity http proxy");

            try {
                httpProxy.stop();
            } catch (Exception e) {
                LOG.error("Failed to stop unity http proxy", e);
            } finally {
                LOG.info("Unity http proxy stopped");
            }

            stateSetter.setState(HState.NOT_CONNECTED);
        }).start();
    }

    @Override
    public void stateChanged(HState oldState, HState newState) {
        if (mode == UnityLaunchMode.WEB && oldState == HState.WAITING_FOR_CLIENT && newState == HState.CONNECTED) {
            // Unregister but do not stop http proxy.
            // We are not stopping the http proxy itself because the hotel websocket is connected to it.
            httpProxy.pause();
            LOG.info("Unity proxy paused");
        }
    }
}
