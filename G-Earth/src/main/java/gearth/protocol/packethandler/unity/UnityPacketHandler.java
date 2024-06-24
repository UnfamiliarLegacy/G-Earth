package gearth.protocol.packethandler.unity;

import gearth.misc.listenerpattern.Observable;
import gearth.protocol.HMessage;
import gearth.protocol.HPacket;
import gearth.protocol.TrafficListener;
import gearth.protocol.packethandler.ByteArrayUtils;
import gearth.protocol.packethandler.PacketHandler;
import gearth.services.extension_handler.ExtensionHandler;

import javax.websocket.Session;
import java.io.IOException;
import java.nio.ByteBuffer;

public class UnityPacketHandler extends PacketHandler {

    private final Session session;
    private final HMessage.Direction direction;

    public UnityPacketHandler(ExtensionHandler extensionHandler, Observable<TrafficListener>[] trafficObservables, Session session, HMessage.Direction direction) {
        super(extensionHandler, trafficObservables);
        this.session = session;
        this.direction = direction;
    }

    @Override
    public boolean sendToStream(byte[] buffer) {
        byte[] prefix = new byte[]{(direction == HMessage.Direction.TOCLIENT ? ((byte)0) : ((byte)1))};
        byte[] combined = ByteArrayUtils.combineByteArrays(prefix, buffer);

        session.getAsyncRemote().sendBinary(ByteBuffer.wrap(combined));
        return true;
    }

    @Override
    public void act(byte[] buffer) throws IOException {
        HMessage hMessage = new HMessage(new HPacket(buffer), direction, currentIndex);
        awaitListeners(hMessage, hMessage1 -> sendToStream(hMessage1.getPacket().toBytes()));
        currentIndex++;
    }
}
