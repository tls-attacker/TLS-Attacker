/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDClientKeyExchangeParser extends ClientKeyExchangeParser<PWDClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    private final KeyExchangeAlgorithm keyExchangeAlgorithm;

    public PWDClientKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        this(pointer, array, version, null);
    }

    public PWDClientKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version,
            KeyExchangeAlgorithm keyExchangeAlgorithm) {
        super(pointer, array, version);
        this.version = version;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    @Override
    protected PWDClientKeyExchangeMessage createHandshakeMessage() {
        return new PWDClientKeyExchangeMessage();
    }

    @Override
    protected void parseHandshakeMessageContent(PWDClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PWDClientKeyExchangeMessage");
        parseElementLength(msg);
        parseElement(msg);
        parseScalarLength(msg);
        parseScalar(msg);
    }

    private void parseElementLength(PWDClientKeyExchangeMessage msg) {
        msg.setElementLength(parseIntField(HandshakeByteLength.PWD_ELEMENT_LENGTH));
        LOGGER.debug("ElementLegnth: " + msg.getElementLength().getValue());
    }

    private void parseElement(PWDClientKeyExchangeMessage msg) {
        msg.setElement(parseByteArrayField(msg.getElementLength().getValue()));
        LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(msg.getElement().getValue()));
    }

    private void parseScalarLength(PWDClientKeyExchangeMessage msg) {
        msg.setScalarLength(parseIntField(HandshakeByteLength.PWD_SCALAR_LENGTH));
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void parseScalar(PWDClientKeyExchangeMessage msg) {
        msg.setScalar(parseByteArrayField(msg.getScalarLength().getValue()));
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(msg.getScalar().getValue()));
    }
}
