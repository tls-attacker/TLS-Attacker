/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RSAClientKeyExchangeHandler<T extends RSAClientKeyExchangeMessage> extends ClientKeyExchangeHandler<T> {

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
