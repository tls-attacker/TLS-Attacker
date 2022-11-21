/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDhClientKeyExchangeParser extends DHClientKeyExchangeParser<PskDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *                      Position in the array where the ClientKeyExchangeParser is supposed to start parsing
     * @param array
     *                      The byte[] which the ClientKeyExchangeParser is supposed to parse
     * @param version
     *                      Version of the Protocol
     * @param config
     *                      A Config used in the current context
     */
    public PskDhClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(PskDhClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKDHClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        super.parseDhParams(msg);
    }

    @Override
    protected PskDhClientKeyExchangeMessage createHandshakeMessage() {
        return new PskDhClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the PSKIdentityLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PskDhClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentity and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PskDhClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(msg.getIdentityLength().getValue()));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
