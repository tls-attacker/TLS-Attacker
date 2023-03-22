/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
        tlsContext.setServerEphemeralRsaExportModulus(
                new BigInteger(1, message.getModulus().getValue()));
        tlsContext.setServerEphemeralRsaExportPublicKey(
                new BigInteger(1, message.getPublicKey().getValue()));
        adjustSelectedSignatureAndHashAlgorithm(message);

        if (message.getKeyExchangeComputations() != null
                && message.getKeyExchangeComputations().getPrivateKey() != null) {
            tlsContext.setServerEphemeralRsaExportPrivateKey(
                    message.getKeyExchangeComputations().getPrivateKey().getValue());
        }
    }
}
