/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHEServerKeyExchangeHandler extends HandshakeMessageHandler<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHEServerKeyExchangeHandler.class);

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected DHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHEServerKeyExchangeParser(pointer, message);
    }

    @Override
    protected DHEServerKeyExchangePreparator getPreparator(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangePreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangeSerializer(message);
    }

    @Override
    protected void adjustTLSContext(DHEServerKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            tlsContext.setPreMasterSecret(message.getComputations().getPremasterSecret().getValue());
        }
        if (message.getComputations().getMasterSecret() != null) {
            tlsContext.setMasterSecret(message.getComputations().getMasterSecret().getValue());
        }
    }
}
