/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.RSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<RSAClientKeyExchangeMessage> {

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public RSAClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new RSAClientKeyExchangeParser(pointer, message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getLastRecordVersion());
    }

    @Override
    public RSAClientKeyExchangePreparator getPreparator(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangePreparator(new DefaultChooser(tlsContext, tlsContext.getConfig()), message);
    }

    @Override
    public RSAClientKeyExchangeSerializer getSerializer(RSAClientKeyExchangeMessage message) {
        return new RSAClientKeyExchangeSerializer(message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(RSAClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }
}
