/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDClientKeyExchangeSerializer
        extends ClientKeyExchangeSerializer<PWDClientKeyExchangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDClientKeyExchangeMessage msg;

    /**
     * Constructor for the ECDHClientKeyExchangerSerializer
     *
     * @param message Message that should be serialized
     */
    public PWDClientKeyExchangeSerializer(PWDClientKeyExchangeMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PWDClientKeyExchangeMessage");
        writeElementLength(msg);
        writeElement(msg);
        writeScalarLength(msg);
        writeScalar(msg);
        return getAlreadySerialized();
    }

    private void writeElementLength(PWDClientKeyExchangeMessage msg) {
        appendInt(msg.getElementLength().getValue(), HandshakeByteLength.PWD_ELEMENT_LENGTH);
        LOGGER.debug("ElementLength: " + msg.getElementLength().getValue());
    }

    private void writeElement(PWDClientKeyExchangeMessage msg) {
        appendBytes(msg.getElement().getValue());
        LOGGER.debug("Element: {}", msg.getElement().getValue());
    }

    private void writeScalarLength(PWDClientKeyExchangeMessage msg) {
        appendInt(msg.getScalarLength().getValue(), HandshakeByteLength.PWD_SCALAR_LENGTH);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void writeScalar(PWDClientKeyExchangeMessage msg) {
        appendBytes(msg.getScalar().getValue());
        LOGGER.debug("Scalar: {}", msg.getScalar().getValue());
    }
}
