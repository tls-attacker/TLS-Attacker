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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<PWDClientKeyExchangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDClientKeyExchangeMessage msg;

    /**
     * Constructor for the ECDHClientKeyExchangerSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PWDClientKeyExchangeSerializer(PWDClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
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
        LOGGER.debug("ElementLegnth: " + msg.getElementLength().getValue());
    }

    private void writeElement(PWDClientKeyExchangeMessage msg) {
        appendBytes(msg.getElement().getValue());
        LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(msg.getElement().getValue()));
    }

    private void writeScalarLength(PWDClientKeyExchangeMessage msg) {
        appendInt(msg.getScalarLength().getValue(), HandshakeByteLength.PWD_SCALAR_LENGTH);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void writeScalar(PWDClientKeyExchangeMessage msg) {
        appendBytes(msg.getScalar().getValue());
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(msg.getScalar().getValue()));
    }
}
