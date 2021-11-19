/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import java.io.InputStream;

public class PskDhClientKeyExchangeHandler extends DHClientKeyExchangeHandler<PskDhClientKeyExchangeMessage> {

    public PskDhClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(PskDhClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
