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
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAServerKeyExchangeParser<T extends RSAServerKeyExchangeMessage>
        extends ServerKeyExchangeParser<T> {
    private static final Logger LOGGER = LogManager.getLogger();

    public RSAServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(RSAServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing RSAServerKeyExchangeMessage");
        parseModulusLength(msg);
        parseModulus(msg);
        parsePublicExponentLength(msg);
        parsePublicExponent(msg);
        if (isTLS12() || isDTLS12()) {
            parseSignatureAndHashAlgorithm(msg);
        }
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    private void parseModulusLength(RSAServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.RSA_MODULUS_LENGTH));
        LOGGER.debug("Modulus Length: {}", msg.getModulusLength().getValue());
    }

    private void parseModulus(RSAServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("Modulus: {}", msg.getModulus().getValue());
    }

    private void parsePublicExponentLength(RSAServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.RSA_PUBLICKEY_LENGTH));
        LOGGER.debug("Public Exponent Length: {}", msg.getPublicKeyLength().getValue());
    }

    private void parsePublicExponent(RSAServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("Public Exponent: {}", msg.getPublicKey().getValue());
    }

    /**
     * Reads the next bytes as the SignatureAndHashAlgorithm and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithm(RSAServerKeyExchangeMessage msg) {
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
    private void parseSignatureLength(RSAServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignature(RSAServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }
}
