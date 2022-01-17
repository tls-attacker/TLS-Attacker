/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EmptyClientKeyExchangeParser<T extends EmptyClientKeyExchangeMessage> extends ClientKeyExchangeParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param context
     */
    public EmptyClientKeyExchangeParser(InputStream stream, ProtocolVersion version, TlsContext context) {
        super(stream, version, context);
    }

    @Override
    protected void parseHandshakeMessageContent(T msg) {
        LOGGER.debug("Parsing EmptyClientKeyExchangeMessage");
    }
}
