/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApplicationMessageSerializer extends ProtocolMessageSerializer<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ApplicationMessage msg;

    /**
     * Constructor for the ApplicationMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ApplicationMessageSerializer(ApplicationMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing ApplicationMessage");
        writeData(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the data of the ApplicationMessage into the final byte[]
     */
    private void writeData(ApplicationMessage msg) {
        appendBytes(msg.getData().getValue());
        LOGGER.debug("Data: " + ArrayConverter.bytesToHexString(msg.getData().getValue()));
    }

}
