/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskDhClientKeyExchangeHandler extends ClientKeyExchangeHandler<PskDhClientKeyExchangeMessage> {

    public PskDhClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskDhClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskDhClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PskDhClientKeyExchangePreparator getPreparator(PskDhClientKeyExchangeMessage message) {
        return new PskDhClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskDhClientKeyExchangeSerializer getSerializer(PskDhClientKeyExchangeMessage message) {
        return new PskDhClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskDhClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
