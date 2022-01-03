/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * Handler for Empty ClientKeyExchange messages
 */
public class EmptyClientKeyExchangeHandler extends ClientKeyExchangeHandler<EmptyClientKeyExchangeMessage> {

    public EmptyClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(EmptyClientKeyExchangeMessage message) {
        spawnNewSession();
    }
}
