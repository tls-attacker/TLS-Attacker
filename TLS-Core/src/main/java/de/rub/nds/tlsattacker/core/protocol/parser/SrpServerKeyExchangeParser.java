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
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpServerKeyExchangeParser
        extends ServerKeyExchangeParser<SrpServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public SrpServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SrpServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing SRPServerKeyExchangeMessage");
        parseModulusLength(msg);
        parseModulus(msg);
        parseGeneratorLength(msg);
        parseGenerator(msg);
        parseSaltLength(msg);
        parseSalt(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            parseSignatureAndHashAlgorithm(msg);
        }
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    /**
     * Reads the next bytes as the nLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseModulusLength(SrpServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.SRP_MODULUS_LENGTH));
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    /**
     * Reads the next bytes as N and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseModulus(SrpServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("Modulus: " + Arrays.toString(msg.getModulus().getValue()));
    }

    /**
     * Reads the next bytes as the saltLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSaltLength(SrpServerKeyExchangeMessage msg) {
        msg.setSaltLength(parseIntField(HandshakeByteLength.SRP_SALT_LENGTH));
        LOGGER.debug("Salt Length: " + msg.getSaltLength().getValue());
    }

    /**
     * Reads the next bytes as Salt and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSalt(SrpServerKeyExchangeMessage msg) {
        msg.setSalt(parseByteArrayField(msg.getSaltLength().getValue()));
        LOGGER.debug("Salt: " + Arrays.toString(msg.getSalt().getValue()));
    }

    /**
     * Reads the next bytes as the gLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseGeneratorLength(SrpServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(parseIntField(HandshakeByteLength.SRP_GENERATOR_LENGTH));
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Reads the next bytes as G and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseGenerator(SrpServerKeyExchangeMessage msg) {
        msg.setGenerator(parseByteArrayField(msg.getGeneratorLength().getValue()));
        LOGGER.debug("G: " + Arrays.toString(msg.getGenerator().getValue()));
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKeyLength(SrpServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.SRP_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSerializedPublicKey(SrpServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: {}", msg.getPublicKey().getValue());
    }

    /**
     * Reads the next bytes as the SignatureAndHashAlgorithm and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithm(SrpServerKeyExchangeMessage msg) {
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
    private void parseSignatureLength(SrpServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignature(SrpServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }
}
