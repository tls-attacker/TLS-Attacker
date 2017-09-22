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
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Message>
 */
public abstract class ExtensionHandler<Message extends ExtensionMessage> {

    protected static final Logger LOGGER = LogManager.getLogger(ExtensionHandler.class.getName());

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
     */
    public abstract void adjustTLSContext(Message message);

    /**
     * Tell the context that the extension was proposed. This should be called
     * in adjustTlsContext(). Makes the extension type available in
     * TlsContext.isProposedTlsExtension{Client,Server}(extType).
     * 
     * @param message
     */
    protected void markExtensionAsProposed(Message message) {
        ExtensionType extType = message.getExtensionTypeConstant();
        ConnectionEndType talkingConEndType = context.getTalkingConnectionEndType();
        if (talkingConEndType == ConnectionEndType.CLIENT) {
            context.setProposedTlsExtensionClient(extType);
        } else if (talkingConEndType == ConnectionEndType.SERVER) {
            context.setProposedTlsExtensionServer(extType);
        }
        LOGGER.debug("Marked extension '" + extType.name() + "' as purposed by " + talkingConEndType);
    }
}
