/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;

/**
 * @param <HandshakeMessageT> The ProtocolMessage that should be handled
 */
public abstract class HandshakeMessageHandler<HandshakeMessageT extends HandshakeMessage<?>>
        extends ProtocolMessageHandler<HandshakeMessageT> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustExtensions(HandshakeMessageT message) {
        LOGGER.debug("Adjusting context for extensions");
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                Handler handler = extension.getHandler(tlsContext);
                handler.adjustContext(extension);
            }
        }
    }

    @Override
    public void prepareAfterParse(HandshakeMessageT message) {
        super.prepareAfterParse(message);

        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = message.getHandshakeMessageType();

                Handler extensionHandler = extensionMessage.getHandler(tlsContext);

                if (extensionMessage instanceof EncryptedServerNameIndicationExtensionMessage) {
                    EncryptedServerNameIndicationExtensionPreparator preparator =
                            (EncryptedServerNameIndicationExtensionPreparator)
                                    ((EncryptedServerNameIndicationExtensionMessage)
                                                    extensionMessage)
                                            .getPreparator(tlsContext);
                    if (message instanceof ClientHelloMessage) {
                        preparator.setClientHelloMessage((ClientHelloMessage) message);
                    }
                    preparator.prepareAfterParse();
                }
            }
        }
    }
}
