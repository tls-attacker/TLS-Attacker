/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *


 * @param <Message>
 */
public abstract class ServerKeyExchangeHandler<Message extends ServerKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    public ServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustPremasterSecret(ServerKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
            tlsContext.setPreMasterSecret(premasterSecret);
            LOGGER.debug("Set PremasterSecret in Context to " + ArrayConverter.bytesToHexString(premasterSecret));
        } else {
            LOGGER.debug("Did not set in Context PremasterSecret");
        }
    }
}
