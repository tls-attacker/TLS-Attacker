/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.DHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.DHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHClientKeyExchangeHandler extends ClientKeyExchangeHandler<DHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");
    
    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHClientKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public DHClientKeyExchangePreparator getPreparator(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(DHClientKeyExchangeMessage message) {
        return new DHClientKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(DHClientKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            tlsContext.setPreMasterSecret(message.getComputations().getPremasterSecret().getValue());
        }
        if (message.getComputations().getMasterSecret() != null) {
            tlsContext.setMasterSecret(message.getComputations().getMasterSecret().getValue());
        }
    }
}
