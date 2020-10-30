/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;

public class RSAServerKeyExchangeParser<T extends RSAServerKeyExchangeMessage> extends ServerKeyExchangeParser<T> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    private final KeyExchangeAlgorithm keyExchangeAlgorithm;

    public RSAServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version,
            KeyExchangeAlgorithm keyExchangeAlgorithm, Config config) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version, config);
        this.version = version;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public RSAServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        this(pointer, array, version, null, config);
    }

    @Override
    protected T createHandshakeMessage() {
        return (T) new RSAServerKeyExchangeMessage();
    }

    @Override
    protected void parseHandshakeMessageContent(RSAServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing RSAServerKeyExchangeMessage");
        parseNLength(msg);
        parseN(msg);
        parseELength(msg);
        parseE(msg);
        // TODO: this.keyExchangeAlgorithm can currently be null, only for test
        // code that needs to be reworked.
        if (this.keyExchangeAlgorithm == null || !this.keyExchangeAlgorithm.isAnon()) {
            if (isTLS12() || isDTLS12()) {
                parseSignatureAndHashAlgorithm(msg);
            }
            parseSignatureLength(msg);
            parseSignature(msg);
        }
    }

    private void parseNLength(RSAServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.RSA_MODULUS_LENGTH));
        LOGGER.debug("NLength: {}", msg.getModulusLength().getValue());
    }

    private void parseN(RSAServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("N: {}", msg.getModulus().getValue());
    }

    private void parseELength(RSAServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.RSA_PUBLICKEY_LENGTH));
        LOGGER.debug("eLength: {}", msg.getPublicKeyLength().getValue());
    }

    private void parseE(RSAServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("e: {}", msg.getPublicKey().getValue());
    }

    /**
     * Checks if the version is TLS12
     *
     * @return True if the used version is TLS12
     */
    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    /**
     * Checks if the version is DTLS12
     *
     * @return True if the used version is DTLS12
     */
    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    /**
     * Reads the next bytes as the SignatureAndHashAlgorithm and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithm(RSAServerKeyExchangeMessage msg) {
        msg.setSignatureAndHashAlgorithm(parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        LOGGER.debug("SignatureAndHashAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    /**
     * Reads the next bytes as the SignatureLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureLength(RSAServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignature(RSAServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

}
