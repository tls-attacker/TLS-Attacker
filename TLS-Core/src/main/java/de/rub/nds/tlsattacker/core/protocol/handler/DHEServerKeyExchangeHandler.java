/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangeHandler<KeyExchangeMessage extends DHEServerKeyExchangeMessage>
        extends ServerKeyExchangeHandler<KeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(KeyExchangeMessage message) {
        adjustDhGenerator(message);
        adjustDhModulus(message);
        adjustServerPublicKey(message);
        adjustSelectedSignatureAndHashAlgorithm(message);
        recognizeNamedGroup();
        if (message.getKeyExchangeComputations() != null
                && message.getKeyExchangeComputations().getPrivateKey() != null) {
            adjustServerPrivateKey(message);
        }
    }

    protected void adjustDhGenerator(KeyExchangeMessage message) {
        tlsContext.setServerEphemeralDhGenerator(
                new BigInteger(1, message.getGenerator().getValue()));
        LOGGER.debug("Dh Generator: {}", tlsContext.getServerEphemeralDhGenerator());
    }

    protected void adjustDhModulus(KeyExchangeMessage message) {
        tlsContext.setServerEphemeralDhModulus(new BigInteger(1, message.getModulus().getValue()));
        LOGGER.debug("Dh Modulus: {}", tlsContext.getServerEphemeralDhModulus());
    }

    protected void adjustServerPublicKey(KeyExchangeMessage message) {
        tlsContext.setServerEphemeralDhPublicKey(
                new BigInteger(1, message.getPublicKey().getValue()));
        LOGGER.debug("Server PublicKey: {}", tlsContext.getServerEphemeralDhPublicKey());
    }

    protected void adjustServerPrivateKey(KeyExchangeMessage message) {
        tlsContext.setServerEphemeralDhPrivateKey(
                message.getKeyExchangeComputations().getPrivateKey().getValue());
        LOGGER.debug("Server PrivateKey: {}", tlsContext.getServerEphemeralDhPrivateKey());
    }

    private void recognizeNamedGroup() {
        BigInteger serverDhGenerator = tlsContext.getServerEphemeralDhGenerator();
        BigInteger serverDhModulus = tlsContext.getServerEphemeralDhModulus();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isDhGroup()) {
                FfdhGroupParameters ffdhGroup = (FfdhGroupParameters) group.getGroupParameters();
                if (serverDhGenerator.equals(ffdhGroup.getGenerator())
                        && serverDhModulus.equals(ffdhGroup.getModulus())) {
                    tlsContext.setSelectedGroup(group);
                    LOGGER.debug(
                            "Set recognized NamedGroup {} of Server Key Exchange message as selected in context",
                            group);
                    break;
                }
            }
        }
    }
}
