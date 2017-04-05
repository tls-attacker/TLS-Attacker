/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ServerKeyExchangePreparator<T extends ServerKeyExchangeMessage> extends
        HandshakeMessagePreparator<ServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    public ServerKeyExchangePreparator(TlsContext context, ServerKeyExchangeMessage message) {
        super(context, message);
    }

}
