/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <Message>
 *            The ServerkeyExchangeMessage that should be handled
 */
public abstract class ServerKeyExchangeHandler<Message extends ServerKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }
}
