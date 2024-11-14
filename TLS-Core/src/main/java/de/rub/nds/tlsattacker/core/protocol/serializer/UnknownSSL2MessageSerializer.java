/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownSSL2Message;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownSSL2MessageSerializer extends SSL2MessageSerializer<UnknownSSL2Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the UnknownMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public UnknownSSL2MessageSerializer(UnknownSSL2Message message) {
        super(message);
    }

    @Override
    protected byte[] serializeMessageContent() {
        LOGGER.debug("Serializing UnknownSSL2Message");
        writeCompleteResultingMessage();
        return getAlreadySerialized();
    }

    /** Writes the CompleteResultingMessage of the UnknownSSL2Message into the final byte[] */
    private void writeCompleteResultingMessage() {
        appendBytes(message.getCompleteResultingMessage().getValue());
        LOGGER.debug(
                "CompleteResultingMessage: {}", message.getCompleteResultingMessage().getValue());
    }
}
