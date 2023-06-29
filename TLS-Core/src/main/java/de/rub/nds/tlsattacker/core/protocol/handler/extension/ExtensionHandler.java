/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <MessageT> The ExtensionMessage that should be handled
 */
public abstract class ExtensionHandler<MessageT extends ExtensionMessage>
        implements Handler<MessageT> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final TlsContext tlsContext;

    public ExtensionHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    /**
     * Adjusts the TLS Context according to the received or sending ProtocolMessage
     *
     * @param message The message for which the Context should be adjusted
     */
    @Override
    public final void adjustContext(MessageT message) {
        markExtensionInContext(message);
        adjustTLSExtensionContext(message);
    }

    public abstract void adjustTLSExtensionContext(MessageT message);

    /**
     * Tell the context that the extension was proposed/negotiated. Makes the extension type
     * available in RecordContext.isExtension{Proposed,Negotiated}(extType).
     *
     * @param message
     */
    private void markExtensionInContext(MessageT message) {
        ExtensionType extType = message.getExtensionTypeConstant();
        ConnectionEndType talkingConEndType = tlsContext.getTalkingConnectionEndType();
        if (talkingConEndType == ConnectionEndType.CLIENT) {
            tlsContext.addProposedExtension(extType);
            LOGGER.debug("Marked extension '" + extType.name() + "' as proposed");
        } else if (talkingConEndType == ConnectionEndType.SERVER) {
            tlsContext.addNegotiatedExtension(extType);
            LOGGER.debug("Marked extension '" + extType.name() + "' as negotiated");
        }
    }
}
