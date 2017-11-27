/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskEcDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskEcDhClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskEcDhClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskEcDhClientKeyExchangeHandler extends ClientKeyExchangeHandler<PskEcDhClientKeyExchangeMessage> {

    public PskEcDhClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskEcDhClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskEcDhClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PskEcDhClientKeyExchangePreparator getPreparator(PskEcDhClientKeyExchangeMessage message) {
        return new PskEcDhClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskEcDhClientKeyExchangeSerializer getSerializer(PskEcDhClientKeyExchangeMessage message) {
        return new PskEcDhClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskEcDhClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }
}
