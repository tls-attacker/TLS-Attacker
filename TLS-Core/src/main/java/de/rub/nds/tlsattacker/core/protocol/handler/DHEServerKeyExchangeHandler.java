/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.GroupFactory;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class DHEServerKeyExchangeHandler<T extends DHEServerKeyExchangeMessage> extends ServerKeyExchangeHandler<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DHEServerKeyExchangeHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(T message) {
        adjustDhGenerator(message);
        adjustDhModulus(message);
        adjustServerPublicKey(message);
        recognizeNamedGroup();
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    private void adjustDhGenerator(T message) {
        context.setServerDhGenerator(new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("Dh Generator: " + context.getServerDhGenerator());
    }

    private void adjustDhModulus(T message) {
        context.setServerDhModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("Dh Modulus: " + context.getServerDhModulus());
    }

    private void adjustServerPublicKey(T message) {
        context.setServerDhPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: " + context.getServerDhPublicKey());
    }

    private void adjustServerPrivateKey(T message) {
        context.setServerDhPrivateKey(message.getComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: " + context.getServerDhPrivateKey());
    }

    private void recognizeNamedGroup() {
        BigInteger serverDhGenerator = context.getServerDhGenerator();
        BigInteger serverDhModulus = context.getServerDhModulus();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isDhGroup()) {
                FFDHEGroup ffdheGroup = GroupFactory.getGroup(group);
                if (serverDhGenerator.equals(ffdheGroup.getG()) && serverDhModulus.equals(ffdheGroup.getP())) {
                    context.setSelectedGroup(group);
                    LOGGER.debug("Set recognized NamedGroup {} of Server Key Exchange message as selected in context",
                        group);
                    break;
                }
            }
        }
    }
}
