/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ServerKeyExchangePreparator<T extends ServerKeyExchangeMessage> extends
        HandshakeMessagePreparator<ServerKeyExchangeMessage> {

    public ServerKeyExchangePreparator(TlsContext context, ServerKeyExchangeMessage message) {
        super(context, message);
    }

}
