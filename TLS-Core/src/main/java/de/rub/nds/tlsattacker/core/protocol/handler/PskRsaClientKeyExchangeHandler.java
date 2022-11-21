/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskRsaClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskRsaClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskRsaClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PskRsaClientKeyExchangeHandler extends RSAClientKeyExchangeHandler<PskRsaClientKeyExchangeMessage> {

    public PskRsaClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PskRsaClientKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PskRsaClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public PskRsaClientKeyExchangePreparator getPreparator(PskRsaClientKeyExchangeMessage message) {
        return new PskRsaClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PskRsaClientKeyExchangeSerializer getSerializer(PskRsaClientKeyExchangeMessage message) {
        return new PskRsaClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(PskRsaClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
