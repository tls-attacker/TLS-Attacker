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
import de.rub.nds.tlsattacker.core.protocol.message.PSKRSAClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.parser.Parser.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKRSAClientKeyExchangeParser extends ClientKeyExchangeParser<PSKRSAClientKeyExchangeMessage> {
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
    public PSKRSAClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(PSKRSAClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKRSAClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    @Override
    protected PSKRSAClientKeyExchangeMessage createHandshakeMessage() {
        return new PSKRSAClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the PSKIdentityLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PSKRSAClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseByteArrayField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentity and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PSKRSAClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(ArrayConverter.bytesToInt(msg.getIdentityLength().getValue())));
        LOGGER.debug("PSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }

    /**
     * Reads the next bytes as the
     * SerializedPublicKeyLength/EncryptedPremasterSecret Length and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKeyLength(PSKRSAClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey/EncryptedPremasterSecret
     * and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(PSKRSAClientKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
