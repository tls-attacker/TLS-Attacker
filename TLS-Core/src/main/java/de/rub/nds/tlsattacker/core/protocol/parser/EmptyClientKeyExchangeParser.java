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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EmptyClientKeyExchangeParser<T extends EmptyClientKeyExchangeMessage> extends ClientKeyExchangeParser<T> {

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
     */
    public EmptyClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(T msg) {
        LOGGER.debug("Parsing EmptyClientKeyExchangeMessage");
    }

    @Override
    protected T createHandshakeMessage() {
        return (T) new EmptyClientKeyExchangeMessage();
    }

}
