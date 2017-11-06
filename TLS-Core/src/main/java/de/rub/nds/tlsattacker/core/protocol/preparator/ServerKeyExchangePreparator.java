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
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * @param <T>
 *            The ServerKeyExchangeMessage that should be prepared
 */
public abstract class ServerKeyExchangePreparator<T extends ServerKeyExchangeMessage> extends
        HandshakeMessagePreparator<ServerKeyExchangeMessage> {

    public ServerKeyExchangePreparator(Chooser chooser, ServerKeyExchangeMessage message) {
        super(chooser, message);
    }

}
