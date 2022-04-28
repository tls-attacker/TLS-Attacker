/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 */
public class DHClientKeyExchangeHandler<T extends DHClientKeyExchangeMessage> extends ClientKeyExchangeHandler<T> {

    private Logger LOGGER = LogManager.getLogger();

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        spawnNewSession();
    }

    private void adjustClientPublicKey(DHClientKeyExchangeMessage message) {
        if (message.getPublicKey().getValue().length == 0) {
            LOGGER.debug("Empty DH Key");
        } else {
            tlsContext.setClientDhPublicKey(new BigInteger(message.getPublicKey().getValue()));
        }
    }
}
