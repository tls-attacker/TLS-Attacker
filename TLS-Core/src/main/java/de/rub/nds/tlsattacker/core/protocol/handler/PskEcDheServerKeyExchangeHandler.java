/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;

public class PskEcDheServerKeyExchangeHandler
        extends ECDHEServerKeyExchangeHandler<PskEcDheServerKeyExchangeMessage> {

    public PskEcDheServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(PskEcDheServerKeyExchangeMessage message) {
        super.adjustECParameter(message);
        if (message.getComputations() != null) {
            tlsContext.setServerEcPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }
}
