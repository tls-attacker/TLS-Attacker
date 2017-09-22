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
import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKClientKeyExchangeParser extends ClientKeyExchangeParser<PSKClientKeyExchangeMessage> {
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
    public PSKClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(PSKClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKClientKeyExchangeMessage");
        parseSerializedPskIdentityLength(msg);
        parseSerializedPskIdentity(msg);
    }

    @Override
    protected PSKClientKeyExchangeMessage createHandshakeMessage() {
        return new PSKClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentityLength and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPskIdentityLength(PSKClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseByteArrayField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("SerializedPSL-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentity and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPskIdentity(PSKClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(ArrayConverter.bytesToInt(msg.getIdentityLength().getValue())));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
