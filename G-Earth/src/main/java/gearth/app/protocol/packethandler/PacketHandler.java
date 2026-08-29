package gearth.app.protocol.packethandler;

import gearth.misc.listenerpattern.Observable;
import gearth.protocol.HMessage;
import gearth.app.protocol.TrafficListener;
import gearth.app.services.extension_handler.ExtensionHandler;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public abstract class PacketHandler {

    private final ExtensionHandler extensionHandler;
    private final Observable<TrafficListener>[] trafficObservables; //get notified on packet send
    protected volatile int currentIndex = 0;
    protected final Object sendLock = new Object();
    protected final Object flushLock = new Object();

    protected PacketHandler(ExtensionHandler extensionHandler, Observable<TrafficListener>[] trafficObservables) {
        this.extensionHandler = extensionHandler;
        this.trafficObservables = trafficObservables;
    }

    public abstract boolean sendToStream(byte[] buffer);

    public abstract void act(byte[] buffer) throws IOException;

    protected void notifyListeners(int i, HMessage message) {
        trafficObservables[i].fireEvent(trafficListener -> {
            message.getPacket().resetReadIndex();
            trafficListener.onCapture(message);
        });
        message.getPacket().resetReadIndex();
    }

    protected void awaitListeners(HMessage message, PacketSender packetSender) {
        notifyListeners(TrafficListener.BEFORE_MODIFICATION, message);
        notifyListeners(TrafficListener.MODIFICATION, message);
        extensionHandler.handle(message, message2 -> {
            notifyListeners(TrafficListener.AFTER_MODIFICATION, message2);
            if (!message2.isBlocked()) {
                packetSender.send(message2);
            }
        });
    }

    /** runs the packet through the extensions and waits up to timeoutMs before giving back the handled message */
    protected HMessage manipulateSync(HMessage message, long timeoutMs) {
        notifyListeners(TrafficListener.BEFORE_MODIFICATION, message);
        notifyListeners(TrafficListener.MODIFICATION, message);
        final HMessage[] result = { message };
        final CountDownLatch latch = new CountDownLatch(1);
        extensionHandler.handle(message, message2 -> {
            notifyListeners(TrafficListener.AFTER_MODIFICATION, message2);
            result[0] = message2;
            latch.countDown();
        });
        try {
            latch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return result[0];
    }

    /** sends the packet through the extensions without waiting and any change they make is not sent on */
    protected void manipulateAsync(HMessage message) {
        notifyListeners(TrafficListener.BEFORE_MODIFICATION, message);
        notifyListeners(TrafficListener.MODIFICATION, message);
        extensionHandler.handle(message, message2 -> notifyListeners(TrafficListener.AFTER_MODIFICATION, message2));
    }

}
