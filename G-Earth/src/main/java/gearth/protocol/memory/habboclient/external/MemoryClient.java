package gearth.protocol.memory.habboclient.external;

import gearth.encoding.HexEncoding;
import gearth.misc.OSValidator;
import gearth.protocol.HConnection;
import gearth.protocol.connection.HClient;
import gearth.protocol.memory.habboclient.HabboClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

public class MemoryClient implements HabboClient {

    private static final Logger logger = LoggerFactory.getLogger(MemoryClient.class);

    private final HConnection connection;

    public MemoryClient(HConnection connection) {
        this.connection = connection;
    }

    @Override
    public List<byte[]> getRC4Tables() {
        final List<byte[]> result = new ArrayList<>();

        try {
            final HashSet<String> potentialTables = dumpTables();

            for (String potentialTable : potentialTables) {
                result.add(HexEncoding.toBytes(potentialTable));
            }
        } catch (IOException | URISyntaxException e) {
            logger.error("Failed to read RC4 possibilities from the client", e);
        }

        // Reverse the list so that the most likely keys are at the top.
        Collections.reverse(result);

        return result;
    }

    private HashSet<String> dumpTables() throws IOException, URISyntaxException {
        String filePath = new File(this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();

        if (OSValidator.isWindows()) {
            filePath += "\\G-MemZ.exe";
        } else {
            filePath += "/G-MemZ";
        }

        final String hotelType = connection.getClientType() == HClient.SHOCKWAVE ? "shockwave" : "flash";
        final ProcessBuilder pb = new ProcessBuilder(filePath, hotelType);
        final Process p = pb.start();

        final HashSet<String> possibleData = new HashSet<>();

        try {
            final BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() == 512) {
                    possibleData.add(line);
                }
            }
        } finally {
            p.destroy();
        }

        return possibleData;
    }
}
