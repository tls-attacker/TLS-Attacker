/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustPremasterSecret(ClientKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
            tlsContext.setPreMasterSecret(premasterSecret);
            LOGGER.debug("Set PremasterSecret in Context to " + ArrayConverter.bytesToHexString(premasterSecret));
        } else {
            LOGGER.debug("Did not set in Context PremasterSecret");
        }
    }

    protected void adjustMasterSecret(ClientKeyExchangeMessage message) {
        if (message.getComputations().getMasterSecret() != null) {
            byte[] masterSecret = message.getComputations().getMasterSecret().getValue();
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set MasterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } else {
            LOGGER.debug("Did not set in Context MasterSecret");
        }
    }
}
