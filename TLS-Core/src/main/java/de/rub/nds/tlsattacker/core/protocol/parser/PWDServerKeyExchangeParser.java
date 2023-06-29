/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDServerKeyExchangeParser
        extends ServerKeyExchangeParser<PWDServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PWDServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(PWDServerKeyExchangeMessage msg) {
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
        LOGGER.debug("Salt: {}", msg.getSalt().getValue());
    }

    private void parseCurveType(PWDServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        LOGGER.debug("CurveType: " + msg.getGroupType().getValue());
    }

    private void parseNamedGroup(PWDServerKeyExchangeMessage msg) {
        msg.setNamedGroup(parseByteArrayField(NamedGroup.LENGTH));
        LOGGER.debug("NamedGroup: {}", msg.getNamedGroup().getValue());
    }

    private void parseElementLength(PWDServerKeyExchangeMessage msg) {
        msg.setElementLength(parseIntField(HandshakeByteLength.PWD_ELEMENT_LENGTH));
        LOGGER.debug("ElementLength: " + msg.getElementLength().getValue());
    }

    private void parseElement(PWDServerKeyExchangeMessage msg) {
        msg.setElement(parseByteArrayField(msg.getElementLength().getValue()));
        LOGGER.debug("Element: {}", msg.getElement().getValue());
    }

    private void parseScalarLength(PWDServerKeyExchangeMessage msg) {
        msg.setScalarLength(parseIntField(HandshakeByteLength.PWD_SCALAR_LENGTH));
        LOGGER.debug("ScalarLength: " + msg.getScalarLength().getValue());
    }

    private void parseScalar(PWDServerKeyExchangeMessage msg) {
        msg.setScalar(parseByteArrayField(msg.getScalarLength().getValue()));
        LOGGER.debug("Scalar: {}", msg.getScalar().getValue());
    }
}
