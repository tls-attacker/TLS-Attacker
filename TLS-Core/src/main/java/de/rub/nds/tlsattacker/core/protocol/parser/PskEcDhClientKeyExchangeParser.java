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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskEcDhClientKeyExchangeParser extends ECDHClientKeyExchangeParser<PskEcDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

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
    public PskEcDhClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(PskEcDhClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKECDHClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        super.parseEcDhParams(msg);
    }

    @Override
    protected PskEcDhClientKeyExchangeMessage createHandshakeMessage() {
        return new PskEcDhClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the PSKIdentityLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PskEcDhClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentity and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PskEcDhClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(msg.getIdentityLength().getValue()));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
