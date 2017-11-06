/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;


public class PSKClientKeyExchangeHandler extends ClientKeyExchangeHandler<PSKClientKeyExchangeMessage> {

    public PSKClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKClientKeyExchangePreparator getPreparator(PSKClientKeyExchangeMessage message) {
        return new PSKClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKClientKeyExchangeSerializer getSerializer(PSKClientKeyExchangeMessage message) {
        return new PSKClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PSKClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }
}
