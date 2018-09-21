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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHEServerKeyExchangeParser<T extends ECDHEServerKeyExchangeMessage> extends ServerKeyExchangeParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    private final KeyExchangeAlgorithm keyExchangeAlgorithm;

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the ServerKeyExchangeParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ServerKeyExchangeParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public ECDHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        this(pointer, array, version, null);
    }

    public ECDHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version,
            KeyExchangeAlgorithm keyExchangeAlgorithm) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    @Override
    protected void parseHandshakeMessageContent(ECDHEServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing ECDHEServerKeyExchangeMessage");
        parseCurveType(msg);
        parseNamedGroup(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
        if (this.keyExchangeAlgorithm == null || !this.keyExchangeAlgorithm.isAnon()) {
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

    @Override
    protected T createHandshakeMessage() {
        return (T) new ECDHEServerKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the CurveType and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCurveType(ECDHEServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        LOGGER.debug("CurveType: " + msg.getGroupType().getValue());
    }

    /**
     * Reads the next bytes as the Curve and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseNamedGroup(ECDHEServerKeyExchangeMessage msg) {
        msg.setNamedGroup(parseByteArrayField(NamedGroup.LENGTH));
        LOGGER.debug("NamedGroup: " + ArrayConverter.bytesToHexString(msg.getNamedGroup().getValue()));
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.ECDHE_PARAM_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    /**
     * Checks if the version is TLS12
     *
     * @param message
     *            Message to check
     * @return True if the used version is TLS12
     */
    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    /**
     * Checks if the version is DTLS12
     *
     * @param message
     *            Message to check
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
    private void parseSignatureAndHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
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
    private void parseSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignature(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }
}
