/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskClientKeyExchangeHandler extends ClientKeyExchangeHandler<PskClientKeyExchangeMessage> {

    public PskClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PskClientKeyExchangePreparator getPreparator(PskClientKeyExchangeMessage message) {
        return new PskClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskClientKeyExchangeSerializer getSerializer(PskClientKeyExchangeMessage message) {
        return new PskClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
