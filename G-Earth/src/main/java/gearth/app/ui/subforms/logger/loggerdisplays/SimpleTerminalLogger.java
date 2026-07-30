package gearth.app.ui.subforms.logger.loggerdisplays;

import gearth.services.packet_info.PacketInfoManager;
import gearth.app.protocol.HConnection;
import gearth.protocol.HMessage;
import gearth.protocol.HPacket;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Jonas on 04/04/18.
 */
class SimpleTerminalLogger implements PacketLogger {

    protected PacketInfoManager packetInfoManager = null;

    @Override
    public void start(HConnection hConnection) {
        packetInfoManager = hConnection.getPacketInfoManager();
//        System.out.println("-- START OF SESSION --");
    }

    @Override
    public void stop() {
//        System.out.println("-- END OF SESSION --");
    }

    @Override
    public void appendSplitLine() {
        System.out.println("-----------------------------------");
    }

    @Override
    public void appendMessage(HPacket packet, int types) {
        appendMessage(packet, types, null);
    }

    @Override
    public void appendMessage(HPacket packet, int types, String extensionName) {
        StringBuilder output = new StringBuilder();

        List<String> tags = new ArrayList<>();
        if ((types & MESSAGE_TYPE.BLOCKED.getValue()) != 0) tags.add("[BLOCKED]");
        if ((types & MESSAGE_TYPE.REPLACED.getValue()) != 0) tags.add("[REPLACED]");
        if ((types & MESSAGE_TYPE.EXTENSION.getValue()) != 0 && extensionName != null) tags.add("[Extension : " + extensionName + "]");
        if (!tags.isEmpty()) output.append(String.join(" ", tags)).append(" ");

        output.append(
                (types & MESSAGE_TYPE.INCOMING.getValue()) != 0 ?
                        "INCOMING " :
                        "OUTGOING "
        );

        if ((types & MESSAGE_TYPE.SHOW_ADDITIONAL_DATA.getValue()) != 0) {
            output.append("(h:").append(packet.headerId()).append(", l:").append(packet.length()).append(") ");
        }

        output.append("--> ");

        output.append( (types & MESSAGE_TYPE.SKIPPED.getValue()) != 0 ?
                "<packet skipped>" :
                packet.toString()
        );

        System.out.println(output.toString());
    }

    @Override
    public void appendStructure(HPacket packet, HMessage.Direction direction) {
        String expr = packet.toExpression(direction, packetInfoManager, true);
        if (!expr.equals("")) {
            System.out.println(expr);
        }
    }
}
