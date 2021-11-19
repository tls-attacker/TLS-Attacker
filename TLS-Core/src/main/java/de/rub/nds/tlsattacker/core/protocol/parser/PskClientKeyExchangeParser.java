/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskClientKeyExchangeParser extends ClientKeyExchangeParser<PskClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                   Version of the Protocol
     * @param tlsContext
     *                   A Config used in the current context
     */
    public PskClientKeyExchangeParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(PskClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
    }

    /**
     * Reads the next bytes as the PSKIdentityLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PskClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PskIdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentity and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PskClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(msg.getIdentityLength().getValue()));
        LOGGER.debug("PskIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
