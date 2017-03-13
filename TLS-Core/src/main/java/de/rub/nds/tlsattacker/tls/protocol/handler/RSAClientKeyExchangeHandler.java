/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<RSAClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(RSAClientKeyExchangeHandler.class);

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public RSAClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new RSAClientKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public RSAClientKeyExchangePreparator getPreparator(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(RSAClientKeyExchangeMessage message) {
        if (message.getComputations().getPremasterSecret() != null) {
            tlsContext.setPreMasterSecret(message.getComputations().getPremasterSecret().getValue());
        }
        if (message.getComputations().getMasterSecret() != null) {
            tlsContext.setMasterSecret(message.getComputations().getMasterSecret().getValue());
        }
    }
}
