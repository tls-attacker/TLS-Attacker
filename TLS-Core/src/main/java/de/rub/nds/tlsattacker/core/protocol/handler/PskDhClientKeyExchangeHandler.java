/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskDhClientKeyExchangeHandler extends DHClientKeyExchangeHandler<PskDhClientKeyExchangeMessage> {

    public PskDhClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskDhClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskDhClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
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
        spawnNewSession();
    }
}
