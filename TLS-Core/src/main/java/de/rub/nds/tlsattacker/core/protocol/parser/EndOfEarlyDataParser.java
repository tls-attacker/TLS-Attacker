/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EndOfEarlyDataParser extends HandshakeMessageParser<EndOfEarlyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EndOfEarlyDataParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(EndOfEarlyDataMessage msg) {
        LOGGER.debug("Parsing EndOfEarlyDataMessage");
        // EndOfEarlyData is always empty
    }
}
