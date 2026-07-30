package gearth.app.ui.subforms.logger.loggerdisplays;

import gearth.protocol.HMessage;
import gearth.protocol.HPacket;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by Jonas on 04/04/18.
 */
class LinuxTerminalLogger extends SimpleTerminalLogger {

    public final static Map<String, String> colorizePackets;
    static {
        //FOR GNOME ONLY, shows up colorized packets
        colorizePackets = new HashMap<>();
        colorizePackets.put("BLOCKED", (char) 27 + "[35m");     // some kind of grey
        colorizePackets.put("INCOMING", (char) 27 + "[31m");    // red
        colorizePackets.put("OUTGOING", (char) 27 + "[34m");    // blue
        colorizePackets.put("REPLACED", (char) 27 + "[33m");    // yellow

        // others:
        colorizePackets.put("INJECTED", "[32m");
        colorizePackets.put("SKIPPED", (char) 27 + "[36m");
        colorizePackets.put("EXPRESSION", (char) 27 + "[36m");
        colorizePackets.put("DEFAULT", (char) 27 + "[0m");
    }

    @Override
    public void appendMessage(HPacket packet, int types) {
        appendMessage(packet, types, null);
    }

    @Override
    public void appendMessage(HPacket packet, int types, String extensionName) {
        StringBuilder output = new StringBuilder();

        List<String> tags = new ArrayList<>();
        if ((types & MESSAGE_TYPE.BLOCKED.getValue()) != 0) tags.add(colorizePackets.get("BLOCKED") + "[BLOCKED]");
        if ((types & MESSAGE_TYPE.REPLACED.getValue()) != 0) tags.add(colorizePackets.get("REPLACED") + "[REPLACED]");
        if ((types & MESSAGE_TYPE.EXTENSION.getValue()) != 0 && extensionName != null) tags.add(colorizePackets.get("INJECTED") + "[Extension : " + extensionName + "]");
        if (!tags.isEmpty()) output.append(String.join(" ", tags)).append(" ");

        output.append(
                (types & MESSAGE_TYPE.INCOMING.getValue()) != 0 ?
                        colorizePackets.get("INCOMING") + "INCOMING " :
                        colorizePackets.get("OUTGOING") + "OUTGOING "
        );

        if ((types & MESSAGE_TYPE.SHOW_ADDITIONAL_DATA.getValue()) != 0) {
            output.append("(h:").append(packet.headerId()).append(", l:").append(packet.length()).append(") ");
        }

        output.append("--> ");

        output.append( (types & MESSAGE_TYPE.SKIPPED.getValue()) != 0 ?
                colorizePackets.get("SKIPPED") +  "<packet skipped>" :
                packet.toString()
        );

        output.append(colorizePackets.get("ENGLISH"));

        System.out.println(output.toString());
    }

    @Override
    public void appendStructure(HPacket packet, HMessage.Direction direction) {
        String expr = packet.toExpression(direction, packetInfoManager, true);
        if (!expr.equals("")) {
            System.out.println(
                    colorizePackets.get("EXPRESSION") +
                            expr +
                            colorizePackets.get("ENGLISH")
            );
        }
    }
}
