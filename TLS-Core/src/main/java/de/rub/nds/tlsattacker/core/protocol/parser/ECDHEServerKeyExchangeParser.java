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
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHEServerKeyExchangeParser<T extends ECDHEServerKeyExchangeMessage>
        extends ServerKeyExchangeParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public ECDHEServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ECDHEServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing ECDHEServerKeyExchangeMessage");
        parseCurveType(msg);
        parseNamedGroup(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
        if (getKeyExchangeAlgorithm() == null || !getKeyExchangeAlgorithm().isAnon()) {
            if (isTLS12() || isDTLS12()) {
                parseSignatureAndHashAlgorithm(msg);
            }
            parseSignatureLength(msg);
            parseSignature(msg);
        }
    }

    protected void parseEcDheParams(T msg) {
        parseCurveType(msg);
        parseNamedGroup(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    /**
     * Reads the next bytes as the CurveType and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCurveType(ECDHEServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        LOGGER.debug("CurveType: " + msg.getGroupType().getValue());
    }

    /**
     * Reads the next bytes as the Curve and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseNamedGroup(ECDHEServerKeyExchangeMessage msg) {
        msg.setNamedGroup(parseByteArrayField(NamedGroup.LENGTH));
        LOGGER.debug("NamedGroup: {}", msg.getNamedGroup().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.ECDHE_PARAM_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }

    /**
     * Reads the next bytes as the SignatureAndHashAlgorithm and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureAndHashAlgorithm(
                parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        LOGGER.debug(
                "SignatureAndHashAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
    }

    /**
     * Reads the next bytes as the SignatureLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignature(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }
}
