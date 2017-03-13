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
import de.rub.nds.tlsattacker.tls.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public abstract class ServerKeyExchangeHandler<Message extends ServerKeyExchangeMessage> extends
        HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");

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

    protected void adjustMasterSecret(ServerKeyExchangeMessage message) {
        if (message.getComputations().getMasterSecret() != null) {
            byte[] masterSecret = message.getComputations().getMasterSecret().getValue();
            tlsContext.setMasterSecret(masterSecret);
            LOGGER.debug("Set MasterSecret in Context to " + ArrayConverter.bytesToHexString(masterSecret));
        } else {
            LOGGER.debug("Did not set in Context MasterSecret");
        }
    }
}
