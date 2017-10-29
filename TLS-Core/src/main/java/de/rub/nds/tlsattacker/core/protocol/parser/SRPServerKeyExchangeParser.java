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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SRPServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.parser.Parser.LOGGER;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SRPServerKeyExchangeParser extends ServerKeyExchangeParser<SRPServerKeyExchangeMessage> {

    private final ProtocolVersion version;

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
    public SRPServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(SRPServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing SRPServerKeyExchangeMessage");
        parseNLength(msg);
        parseN(msg);
        parsegLength(msg);
        parseG(msg);
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

    @Override
    protected SRPServerKeyExchangeMessage createHandshakeMessage() {
        return new SRPServerKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the nLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseNLength(SRPServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.SRP_MODULUS_LENGTH));
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    /**
     * Reads the next bytes as N and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseN(SRPServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("Modulus: " + msg.getModulus().getValue());
    }

    /**
     * Reads the next bytes as the saltLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSaltLength(SRPServerKeyExchangeMessage msg) {
        msg.setSaltLength(parseIntField(HandshakeByteLength.SRP_SALT_LENGTH));
        LOGGER.debug("Salt Length: " + msg.getSaltLength().getValue());
    }

    /**
     * Reads the next bytes as Salt and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSalt(SRPServerKeyExchangeMessage msg) {
        msg.setSalt(parseByteArrayField(msg.getSaltLength().getValue()));
        LOGGER.debug("Salt: " + msg.getSalt().getValue().toString());
    }

    /**
     * Reads the next bytes as the gLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsegLength(SRPServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(parseIntField(HandshakeByteLength.SRP_GENERATOR_LENGTH));
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Reads the next bytes as G and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseG(SRPServerKeyExchangeMessage msg) {
        msg.setGenerator(parseByteArrayField(msg.getGeneratorLength().getValue()));
        LOGGER.debug("G: " + msg.getGenerator().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKeyLength(SRPServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.SRP_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(SRPServerKeyExchangeMessage msg) {
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
    private void parseSignatureAndHashAlgorithm(SRPServerKeyExchangeMessage msg) {
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
    private void parseSignatureLength(SRPServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignature(SRPServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }
}
