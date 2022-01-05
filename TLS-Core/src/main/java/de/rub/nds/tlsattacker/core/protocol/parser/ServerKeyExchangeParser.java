/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;

/**
 * @param <T>
 *            The ServerKeyExchangeMessage that should be parsed
 */
public abstract class ServerKeyExchangeParser<T extends ServerKeyExchangeMessage> extends HandshakeMessageParser<T> {

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *                     Position in the array where the ServerKeyExchangeParser is supposed to start parsing
     * @param array
     *                     The byte[] which the ServerKeyExchangeParser is supposed to parse
     * @param expectedType
     *                     The Handshake message type that is expected
     * @param version
     *                     Version of the Protocol
     * @param config
     *                     A Config used in the current context
     */
    public ServerKeyExchangeParser(int pointer, byte[] array, HandshakeMessageType expectedType,
        ProtocolVersion version, Config config) {
        super(pointer, array, expectedType, version, config);
    }

}
