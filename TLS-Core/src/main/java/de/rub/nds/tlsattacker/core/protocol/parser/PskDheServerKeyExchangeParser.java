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
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.parser.Parser.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskDheServerKeyExchangeParser extends ServerKeyExchangeParser<PskDheServerKeyExchangeMessage> {

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
    public PskDheServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(PskDheServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKDHEServerKeyExchangeMessage");
        parsePskIdentityHintLength(msg);
        parsePskIdentityHint(msg);
        parsepLength(msg);
        parseP(msg);
        parsegLength(msg);
        parseG(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    @Override
    protected PskDheServerKeyExchangeMessage createHandshakeMessage() {
        return new PskDheServerKeyExchangeMessage();
    }

    private void parsePskIdentityHintLength(PskDheServerKeyExchangeMessage msg) {
        msg.setIdentityHintLength(parseByteArrayField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("SerializedPSL-IdentityLength: " + msg.getIdentityHintLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentityHint and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityHint(PskDheServerKeyExchangeMessage msg) {
        msg.setIdentityHint(parseByteArrayField(ArrayConverter.bytesToInt(msg.getIdentityHintLength().getValue())));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }

    /**
     * Reads the next bytes as the pLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsepLength(PskDheServerKeyExchangeMessage msg) {
        msg.setModulusLength(parseIntField(HandshakeByteLength.DH_MODULUS_LENGTH));
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /**
     * Reads the next bytes as P and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseP(PskDheServerKeyExchangeMessage msg) {
        msg.setModulus(parseByteArrayField(msg.getModulusLength().getValue()));
        LOGGER.debug("P: " + msg.getModulus().getValue());
    }

    /**
     * Reads the next bytes as the gLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsegLength(PskDheServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(parseIntField(HandshakeByteLength.DH_GENERATOR_LENGTH));
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Reads the next bytes as G and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseG(PskDheServerKeyExchangeMessage msg) {
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
    private void parseSerializedPublicKeyLength(PskDheServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(PskDheServerKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
