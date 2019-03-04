/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HeartbeatExtensionParser extends ExtensionParser<HeartbeatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HeartbeatExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(HeartbeatExtensionMessage msg) {
        LOGGER.debug("Parsing HeartbeatExtensionMessage");
        parseHeartbeatMode(msg);
    }

    @Override
    protected HeartbeatExtensionMessage createExtensionMessage() {
        return new HeartbeatExtensionMessage();
    }

    /**
     * Reads the next bytes as the HeartbeatMode of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseHeartbeatMode(HeartbeatExtensionMessage msg) {
        msg.setHeartbeatMode(parseByteArrayField(ExtensionByteLength.HEARTBEAT_MODE));
        LOGGER.debug("HeartbeatMode: " + ArrayConverter.bytesToHexString(msg.getHeartbeatMode().getValue()));
    }

}
