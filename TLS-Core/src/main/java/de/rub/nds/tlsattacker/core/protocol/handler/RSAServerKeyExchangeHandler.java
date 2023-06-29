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
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import java.math.BigInteger;

public class RSAServerKeyExchangeHandler
        extends ServerKeyExchangeHandler<RSAServerKeyExchangeMessage> {

    public RSAServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(RSAServerKeyExchangeMessage message) {
        tlsContext.setServerRSAModulus(new BigInteger(1, message.getModulus().getValue()));
        tlsContext.setServerRSAPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        if (message.getComputations() != null
                && message.getComputations().getPrivateKey() != null) {
            tlsContext.setServerRSAPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }
}
