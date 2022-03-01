/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EndOfEarlyDataParser extends HandshakeMessageParser<EndOfEarlyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EndOfEarlyDataParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, HandshakeMessageType.END_OF_EARLY_DATA, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(EndOfEarlyDataMessage msg) {
        LOGGER.debug("Parsing EndOfEarlyDataMessage");
        // EndOfEarlyData is always empty
    }
}
