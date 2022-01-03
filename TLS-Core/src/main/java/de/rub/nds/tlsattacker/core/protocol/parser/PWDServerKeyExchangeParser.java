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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDServerKeyExchangeParser extends ServerKeyExchangeParser<PWDServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    private final KeyExchangeAlgorithm keyExchangeAlgorithm;

    public PWDServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        this(pointer, array, version, null, config);
    }

    public PWDServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version,
        KeyExchangeAlgorithm keyExchangeAlgorithm, Config config) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version, config);
        this.version = version;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    @Override
    protected PWDServerKeyExchangeMessage createHandshakeMessage() {
        return new PWDServerKeyExchangeMessage();
    }

    @Override
    protected void parseHandshakeMessageContent(PWDServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PWDServerKeyExchangeMessage");
        parseSaltLength(msg);
        parseSalt(msg);
        parseCurveType(msg);
        parseNamedGroup(msg);
        parseElementLength(msg);
        parseElement(msg);
        parseScalarLength(msg);
        parseScalar(msg);
    }

    private void parseSaltLength(PWDServerKeyExchangeMessage msg) {
        msg.setSaltLength(parseIntField(HandshakeByteLength.PWD_SALT_LENGTH));
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    private void parseSalt(PWDServerKeyExchangeMessage msg) {
        msg.setSalt(parseByteArrayField(msg.getSaltLength().getValue()));
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt().getValue()));
    }

    private void parseCurveType(PWDServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        LOGGER.debug("CurveType: " + msg.getGroupType().getValue());
    }

    private void parseNamedGroup(PWDServerKeyExchangeMessage msg) {
        msg.setNamedGroup(parseByteArrayField(NamedGroup.LENGTH));
        LOGGER.debug("NamedGroup: " + ArrayConverter.bytesToHexString(msg.getNamedGroup().getValue()));
    }

    private void parseElementLength(PWDServerKeyExchangeMessage msg) {
        msg.setElementLength(parseIntField(HandshakeByteLength.PWD_ELEMENT_LENGTH));
        LOGGER.debug("ElementLength: " + msg.getElementLength().getValue());
    }

    private void parseElement(PWDServerKeyExchangeMessage msg) {
        msg.setElement(parseByteArrayField(msg.getElementLength().getValue()));
        LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(msg.getElement().getValue()));
    }

    private void parseScalarLength(PWDServerKeyExchangeMessage msg) {
        msg.setScalarLength(parseIntField(HandshakeByteLength.PWD_SCALAR_LENGTH));
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void parseScalar(PWDServerKeyExchangeMessage msg) {
        msg.setScalar(parseByteArrayField(msg.getScalarLength().getValue()));
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(msg.getScalar().getValue()));
    }
}
