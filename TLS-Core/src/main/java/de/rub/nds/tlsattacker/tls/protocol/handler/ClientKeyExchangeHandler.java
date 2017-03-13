/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");
    
    protected KeyExchangeAlgorithm keyExchangeAlgorithm;

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }
}
