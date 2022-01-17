/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class SrpServerKeyExchangeHandler extends ServerKeyExchangeHandler<SrpServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrpServerKeyExchangeHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(SrpServerKeyExchangeMessage message) {
        adjustSRPGenerator(message);
        adjustSRPModulus(message);
        adjustSalt(message);
        adjustServerPublicKey(message);
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    private void adjustSRPGenerator(SrpServerKeyExchangeMessage message) {
        context.setSRPGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("SRP Generator: " + context.getSRPGenerator());
    }

    private void adjustSRPModulus(SrpServerKeyExchangeMessage message) {
        context.setSRPModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("SRP Modulus: " + context.getSRPModulus());
    }

    private void adjustServerPublicKey(SrpServerKeyExchangeMessage message) {
        context.setServerSRPPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + context.getServerSRPPublicKey());
    }

    private void adjustServerPrivateKey(SrpServerKeyExchangeMessage message) {
        context.setServerSRPPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + context.getServerSRPPrivateKey());
    }

    private void adjustSalt(SrpServerKeyExchangeMessage message) {
        context.setSRPServerSalt(message.getSalt().getValue());
        LOGGER.debug("SRP Salt: " + ArrayConverter.bytesToHexString(context.getSRPServerSalt()));
    }
}
