/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.RequestConnectionIdMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RequestConnectionIdParser extends HandshakeMessageParser<RequestConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RequestConnectionIdParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(RequestConnectionIdMessage message) {
        LOGGER.debug("Parsing RequestConnectionIdMessage");
        parseNumCids(message);
    }

    private void parseNumCids(RequestConnectionIdMessage message) {
        message.setNumberOfConnectionIds(
                parseIntField(HandshakeByteLength.REQUEST_CONNECTION_ID_NUMBER_CIDS_LENGTH));
        LOGGER.debug("NumberOfConnectionIds: " + message.getNumberOfConnectionIds().getValue());
    }
}
