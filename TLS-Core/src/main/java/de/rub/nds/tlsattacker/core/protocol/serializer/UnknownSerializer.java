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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownSerializer extends ProtocolMessageSerializer<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final UnknownMessage msg;

    /**
     * Constructor for the UnknownMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public UnknownSerializer(UnknownMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing UnknownMessage");
        writeCompleteResultinMessage(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CompleteResultingMessage of the UnknownMessage into the final
     * byte[]
     */
    private void writeCompleteResultinMessage(UnknownMessage msg) {
        appendBytes(msg.getCompleteResultingMessage().getValue());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }

}
