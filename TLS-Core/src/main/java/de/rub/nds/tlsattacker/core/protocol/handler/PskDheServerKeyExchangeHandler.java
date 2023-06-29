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
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDheServerKeyExchangeHandler
        extends DHEServerKeyExchangeHandler<PskDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PskDheServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(PskDheServerKeyExchangeMessage message) {
        adjustPSKGenerator(message);
        adjustPSKModulus(message);
        adjustServerPublicKey(message);
        if (message.getComputations() != null
                && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    private void adjustPSKGenerator(PskDheServerKeyExchangeMessage message) {
        tlsContext.setPSKGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("PSK Generator: " + tlsContext.getPSKGenerator());
    }

    private void adjustPSKModulus(PskDheServerKeyExchangeMessage message) {
        tlsContext.setPSKModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("PSK Modulus: " + tlsContext.getPSKModulus());
    }

    private void adjustServerPublicKey(PskDheServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + tlsContext.getServerPSKPublicKey());
    }

    private void adjustServerPrivateKey(PskDheServerKeyExchangeMessage message) {
        tlsContext.setServerPSKPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + tlsContext.getServerPSKPrivateKey());
    }
}
