/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PSKRSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKRSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKRSAClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKRSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKRSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<PSKRSAClientKeyExchangeMessage> {

    public PSKRSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKRSAClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKRSAClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKRSAClientKeyExchangePreparator getPreparator(PSKRSAClientKeyExchangeMessage message) {
        return new PSKRSAClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKRSAClientKeyExchangeSerializer getSerializer(PSKRSAClientKeyExchangeMessage message) {
        return new PSKRSAClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(PSKRSAClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }
}
