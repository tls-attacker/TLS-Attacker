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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
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
            KeyShareExtensionHandler keyShareHandler = null;
            KeyShareExtensionMessage keyShareExtension = null;
            for (ExtensionMessage extension : message.getExtensions()) {
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                        extension.getExtensionTypeConstant(), handshakeMessageType);
                if (handler instanceof KeyShareExtensionHandler) {
                    keyShareHandler = (KeyShareExtensionHandler) handler;
                    keyShareExtension = (KeyShareExtensionMessage) extension;
                } else {
                    handler.adjustTLSContext(extension);
                }
            }
            if (keyShareHandler != null) // delay KeyShare to process PSK first
            {
                keyShareHandler.adjustTLSContext(keyShareExtension);
            }
        }
    }
}
