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
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PWDServerKeyExchangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDServerKeyExchangeMessage msg;

    /**
     * Constructor for the ECDHServerKeyExchangerSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PWDServerKeyExchangeSerializer(PWDServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PWDServerKeyExchangeMessage");
        writeSaltLength(msg);
        writeSalt(msg);
        writeCurveType(msg);
        writeNamedGroup(msg);
        writeElementLength(msg);
        writeElement(msg);
        writeScalarLength(msg);
        writeScalar(msg);
        return getAlreadySerialized();
    }

    private void writeSaltLength(PWDServerKeyExchangeMessage msg) {
        appendInt(msg.getSaltLength().getValue(), HandshakeByteLength.PWD_SALT_LENGTH);
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    private void writeSalt(PWDServerKeyExchangeMessage msg) {
        appendBytes(msg.getSalt().getValue());
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt().getValue()));
    }

    private void writeCurveType(PWDServerKeyExchangeMessage msg) {
        appendByte(msg.getGroupType().getValue());
        LOGGER.debug("CurveType: " + msg.getGroupType().getValue());
    }

    private void writeNamedGroup(PWDServerKeyExchangeMessage msg) {
        appendBytes(msg.getNamedGroup().getValue());
        LOGGER.debug("NamedGroup: " + ArrayConverter.bytesToHexString(msg.getNamedGroup().getValue()));
    }

    private void writeElementLength(PWDServerKeyExchangeMessage msg) {
        appendInt(msg.getElementLength().getValue(), HandshakeByteLength.PWD_ELEMENT_LENGTH);
        LOGGER.debug("ElementLegnth: " + msg.getElementLength().getValue());
    }

    private void writeElement(PWDServerKeyExchangeMessage msg) {
        appendBytes(msg.getElement().getValue());
        LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(msg.getElement().getValue()));
    }

    private void writeScalarLength(PWDServerKeyExchangeMessage msg) {
        appendInt(msg.getScalarLength().getValue(), HandshakeByteLength.PWD_SCALAR_LENGTH);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void writeScalar(PWDServerKeyExchangeMessage msg) {
        appendBytes(msg.getScalar().getValue());
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(msg.getScalar().getValue()));
    }
}
