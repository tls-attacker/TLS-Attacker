/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageSerializer extends ProtocolMessageSerializer<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the UnknownMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public UnknownMessageSerializer(UnknownMessage message, ProtocolVersion version) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing UnknownMessage");
        writeCompleteResultingMessage();
        return getAlreadySerialized();
    }

    /**
     * Writes the CompleteResultingMessage of the UnknownMessage into the final byte[]
     */
    private void writeCompleteResultingMessage() {
        appendBytes(message.getCompleteResultingMessage().getValue());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(message.getCompleteResultingMessage().getValue()));
    }

}
