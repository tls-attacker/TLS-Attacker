/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <MessageT> The ServerKeyExchangeMessage that should be handled
 */
public abstract class ServerKeyExchangeHandler<MessageT extends ServerKeyExchangeMessage>
        extends HandshakeMessageHandler<MessageT> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustSelectedSignatureAndHashAlgorithm(MessageT message) {
        if (message.getSignatureAndHashAlgorithm() != null
                && message.getSignatureAndHashAlgorithm().getValue() != null) {

            byte[] sigHashBytes = message.getSignatureAndHashAlgorithm().getValue();
            SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(sigHashBytes);
            tlsContext.setSelectedSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
        }
    }
}
