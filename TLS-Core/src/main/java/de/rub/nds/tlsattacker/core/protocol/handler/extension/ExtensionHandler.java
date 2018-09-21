/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <Message>
 *            The ExtensionMessage that should be handled
 */
public abstract class ExtensionHandler<Message extends ExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final TlsContext context;

    public ExtensionHandler(TlsContext context) {
        this.context = context;
    }

    public abstract ExtensionParser getParser(byte[] message, int pointer);

    public abstract ExtensionPreparator getPreparator(Message message);

    public abstract ExtensionSerializer getSerializer(Message message);

    /**
     * Adjusts the TLS Context according to the received or sending
     * ProtocolMessage
     *
     * @param message
     *            The message for which the Context should be adjusted
     */
    public final void adjustTLSContext(Message message) {
        markExtensionInContext(message);
        adjustTLSExtensionContext(message);
    }

    public abstract void adjustTLSExtensionContext(Message message);

    /**
     * Tell the context that the extension was proposed/negotiated. Makes the
     * extension type available in
     * TlsContext.isExtension{Proposed,Negotiated}(extType).
     *
     * @param message
     */
    private void markExtensionInContext(Message message) {
        ExtensionType extType = message.getExtensionTypeConstant();
        ConnectionEndType talkingConEndType = context.getTalkingConnectionEndType();
        if (talkingConEndType == ConnectionEndType.CLIENT) {
            context.addProposedExtension(extType);
            LOGGER.debug("Marked extension '" + extType.name() + "' as proposed");
        } else if (talkingConEndType == ConnectionEndType.SERVER) {
            context.addNegotiatedExtension(extType);
            LOGGER.debug("Marked extension '" + extType.name() + "' as negotiated");
        }
    }
}
