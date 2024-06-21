package gearth.protocol.packethandler;

import gearth.misc.listenerpattern.Observable;
import gearth.protocol.HMessage;
import gearth.protocol.TrafficListener;
import gearth.services.extension_handler.ExtensionHandler;

import java.io.IOException;

public abstract class PacketHandler {

    protected final ExtensionHandler extensionHandler;
    private final Object[] trafficObservables; //get notified on packet send
    protected volatile int currentIndex = 0;
    protected final Object sendLock = new Object();

    protected PacketHandler(ExtensionHandler extensionHandler, Object[] trafficObservables) {
        this.extensionHandler = extensionHandler;
        this.trafficObservables = trafficObservables;
    }


    public abstract boolean sendToStream(byte[] buffer);

    public abstract void act(byte[] buffer) throws IOException;

    protected void notifyListeners(int i, HMessage message) {
        ((Observable<TrafficListener>) trafficObservables[i]).fireEvent(trafficListener -> {
            message.getPacket().resetReadIndex();
            trafficListener.onCapture(message);
        });
        message.getPacket().resetReadIndex();
    }

    protected void awaitListeners(HMessage message, PacketSender packetSender) {
        notifyListeners(0, message);
        notifyListeners(1, message);
        extensionHandler.handle(message, message2 -> {
            notifyListeners(2, message2);
            if (!message2.isBlocked()) {
                packetSender.send(message2);
            }
        });
    }

}
