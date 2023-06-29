/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHClientKeyExchangeParser<T extends DHClientKeyExchangeMessage>
        extends ClientKeyExchangeParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public DHClientKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(T msg) {
        LOGGER.debug("Parsing DHClientKeyExchangeMessage");
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    protected void parseDhParams(T msg) {
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKey(T msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }
}
