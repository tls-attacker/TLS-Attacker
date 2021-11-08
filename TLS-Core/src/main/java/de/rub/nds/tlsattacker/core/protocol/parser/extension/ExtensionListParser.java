package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionListParser extends Parser<List<ExtensionMessage>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionEndType talkingConnectionEndType;
    private final Config config;
    private final ProtocolVersion selectedVersion;
    private final boolean helloRetryRequestHint;

    public ExtensionListParser(InputStream stream, Config config, ConnectionEndType talkingConnectionEndType, ProtocolVersion selectedVersion, boolean helloRetryRequestHint) {
        super(stream);
        this.talkingConnectionEndType = talkingConnectionEndType;
        this.config = config;
        this.selectedVersion = selectedVersion;
        this.helloRetryRequestHint = helloRetryRequestHint;
    }

    @Override
    public List<ExtensionMessage> parse() {
        List<ExtensionMessage> extensionList = new LinkedList();
        while (getBytesLeft() > 0) {
            byte[] typeBytes = parseByteArrayField(ExtensionByteLength.TYPE);
            ExtensionType extensionType = ExtensionType.getExtensionType(typeBytes);
            LOGGER.debug("ExtensionType: {} ({})" + ArrayConverter.bytesToHexString(typeBytes), extensionType);
            int length = parseExtensionLength();
            byte[] extensionPayload = parseByteArrayField(length);
            ExtensionParser parser = ExtensionParserFactory.getExtensionParser(new ByteArrayInputStream(extensionPayload), extensionType, config, talkingConnectionEndType, selectedVersion);
            if (parser instanceof KeyShareExtensionParser) {
                ((KeyShareExtensionParser) parser).setHelloRetryRequestHint(helloRetryRequestHint);
            }
            ExtensionMessage extension = parser.parse();
            extension.setExtensionType(typeBytes);
            extension.setExtensionLength(length);
            extension.setExtensionBytes(ArrayConverter.concatenate(typeBytes, ArrayConverter.intToBytes(length, ExtensionByteLength.EXTENSIONS_LENGTH), extensionPayload));
            extensionList.add(extension);
        }
        return extensionList;
    }

    /**
     * Reads the next bytes as the length of the Extension and writes them in
     * the message
     *
     * @param msg Message to write in
     */
    private int parseExtensionLength() {
        int length = parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH);
        LOGGER.debug("ExtensionLength: {}", length);
        return length;
    }

}
