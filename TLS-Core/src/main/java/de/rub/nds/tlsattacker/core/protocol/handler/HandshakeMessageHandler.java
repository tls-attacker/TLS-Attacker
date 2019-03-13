/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @param <ProtocolMessage>
 *            The ProtocolMessage that should be handled
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
        ProtocolMessageHandler<ProtocolMessage> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustExtensions(ProtocolMessage message, HandshakeMessageType handshakeMessageType) {
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                if (extension instanceof HRRKeyShareExtensionMessage) { // TODO
                                                                        // fix
                                                                        // design
                                                                        // flaw
                    handshakeMessageType = HandshakeMessageType.HELLO_RETRY_REQUEST;
                }
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                        extension.getExtensionTypeConstant(), handshakeMessageType);
                handler.adjustTLSContext(extension);
            }
        }
    }
}
