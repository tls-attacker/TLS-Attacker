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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.parser.Parser.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHClientKeyExchangeParser extends ClientKeyExchangeParser<PSKDHClientKeyExchangeMessage> {
    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the ClientKeyExchangeParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ClientKeyExchangeParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public PSKDHClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(PSKDHClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKDHClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    @Override
    protected PSKDHClientKeyExchangeMessage createHandshakeMessage() {
        return new PSKDHClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentityLength and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PSKDHClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseByteArrayField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentity and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PSKDHClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(ArrayConverter.bytesToInt(msg.getIdentityLength().getValue())));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKeyLength(PSKDHClientKeyExchangeMessage message) {
        message.setPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + message.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(PSKDHClientKeyExchangeMessage message) {
        message.setPublicKey(parseByteArrayField(message.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(message.getPublicKey().getValue()));
    }
}
