/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.RequestConnectionIdMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RequestConnectionIdHandler extends HandshakeMessageHandler<RequestConnectionIdMessage> {
    
    private static final Logger LOGGER = LogManager.getLogger();
        
    public RequestConnectionIdHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(RequestConnectionIdMessage message) {
        LOGGER.debug(
                "Set number of requested Connection IDs in Context to "
                        + message.getNumberOfConnectionIds().getValue());
        tlsContext.setNumberOfRequestedConnectionIds(message.getNumberOfConnectionIds().getValue());
    }
}
