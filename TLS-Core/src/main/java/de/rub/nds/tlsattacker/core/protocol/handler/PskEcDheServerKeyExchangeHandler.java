/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskEcDheServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskEcDheServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskEcDheServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskEcDheServerKeyExchangeHandler extends ECDHEServerKeyExchangeHandler<PskEcDheServerKeyExchangeMessage> {

    public PskEcDheServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskEcDheServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskEcDheServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PskEcDheServerKeyExchangePreparator getPreparator(PskEcDheServerKeyExchangeMessage message) {
        return new PskEcDheServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskEcDheServerKeyExchangeSerializer getSerializer(PskEcDheServerKeyExchangeMessage message) {
        return new PskEcDheServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskEcDheServerKeyExchangeMessage message) {
        super.adjustECParameter(message);
        if (message.getComputations() != null) {
            tlsContext.setServerEcPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }
}
