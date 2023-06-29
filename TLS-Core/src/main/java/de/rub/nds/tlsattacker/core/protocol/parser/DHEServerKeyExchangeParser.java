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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangeParser<T extends DHEServerKeyExchangeMessage>
        extends ServerKeyExchangeParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public DHEServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(DHEServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing DHEServerKeyExchangeMessage");
        parsePLength(msg);
        parseP(msg);
        parseGLength(msg);
        parseG(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
        // TODO: this.keyExchangeAlgorithm can currently be null, only for test
        // code that needs to be reworked.
        if (getKeyExchangeAlgorithm() == null || !getKeyExchangeAlgorithm().isAnon()) {
            if (isTLS12() || isDTLS12()) {
                parseSignatureAndHashAlgorithm(msg);
            }
            parseSignatureLength(msg);
            parseSignature(msg);
        }
    }

    protected void parseDheParams(T msg) {
        parsePLength(msg);
        parseP(msg);
        parseGLength(msg);
        parseG(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    /**
     * Reads the next bytes as the pLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePLength(DHEServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.DH_MODULUS_LENGTH));
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /**
     * Reads the next bytes as P and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseP(DHEServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("P: " + Arrays.toString(msg.getModulus().getValue()));
    }

    /**
     * Reads the next bytes as the gLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseGLength(DHEServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(parseIntField(HandshakeByteLength.DH_GENERATOR_LENGTH));
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Reads the next bytes as G and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseG(DHEServerKeyExchangeMessage msg) {
        msg.setGenerator(parseByteArrayField(msg.getGeneratorLength().getValue()));
        LOGGER.debug("G: " + Arrays.toString(msg.getGenerator().getValue()));
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKeyLength(DHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }

    /**
     * Reads the next bytes as the SignatureAndHashAlgorithm and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithm(DHEServerKeyExchangeMessage msg) {
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
    private void parseSignatureLength(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignature(DHEServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }
}
