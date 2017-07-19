/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage> {

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHClientKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ECDHClientKeyExchangePreparator getPreparator(ECDHClientKeyExchangeMessage message) {
        return new ECDHClientKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public ECDHClientKeyExchangeSerializer getSerializer(ECDHClientKeyExchangeMessage message) {
        return new ECDHClientKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ECDHClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }
}
