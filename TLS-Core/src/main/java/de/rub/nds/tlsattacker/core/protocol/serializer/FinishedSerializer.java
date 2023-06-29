/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FinishedSerializer extends HandshakeMessageSerializer<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final FinishedMessage msg;

    /**
     * Constructor for the FinishedMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public FinishedSerializer(FinishedMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing FinishedMessage");
        writeVerifyData(msg);
        return getAlreadySerialized();
    }

    /** Writes the VerifyData of the ECDHEServerKeyExchangeMessage into the final byte[] */
    private void writeVerifyData(FinishedMessage msg) {
        appendBytes(msg.getVerifyData().getValue());
        LOGGER.debug("VerifyData: {}", msg.getVerifyData().getValue());
    }
}
