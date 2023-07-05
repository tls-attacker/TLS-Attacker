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
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;

public class PWDClientKeyExchangeHandler
        extends ClientKeyExchangeHandler<PWDClientKeyExchangeMessage> {

    public PWDClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(PWDClientKeyExchangeMessage message) {
        if (message.getComputations() != null) {
            tlsContext.setPWDPE(message.getComputations().getPasswordElement());
            tlsContext.setClientPWDPrivate(message.getComputations().getPrivateKeyScalar());
        }

        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
