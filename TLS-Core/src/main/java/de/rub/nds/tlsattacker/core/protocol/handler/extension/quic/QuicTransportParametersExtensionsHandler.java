/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension.quic;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicTransportParametersExtensionsHandler
        extends ExtensionHandler<QuicTransportParametersExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicTransportParametersExtensionsHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(QuicTransportParametersExtensionMessage message) {
        LOGGER.debug("Adjust Quic Transport Parameters in Context to:\n" + message);
        tlsContext
                .getContext()
                .getQuicContext()
                .setReceivedTransportParameters(message.getQuicTransportParameters());
    }
}
