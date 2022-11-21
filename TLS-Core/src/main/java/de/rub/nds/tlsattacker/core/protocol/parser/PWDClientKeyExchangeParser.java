/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDClientKeyExchangeParser extends ClientKeyExchangeParser<PWDClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    private final KeyExchangeAlgorithm keyExchangeAlgorithm;

    public PWDClientKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        this(pointer, array, version, null, config);
    }

    public PWDClientKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version,
        KeyExchangeAlgorithm keyExchangeAlgorithm, Config config) {
        super(pointer, array, version, config);
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
        LOGGER.debug("ElementLength: " + msg.getElementLength().getValue());
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
