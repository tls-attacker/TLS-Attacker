/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @param <HandshakeMessageT>
 *                            The ProtocolMessage that should be handled
 */
public abstract class HandshakeMessageHandler<HandshakeMessageT extends HandshakeMessage>
    extends TlsMessageHandler<HandshakeMessageT> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    protected void adjustExtensions(HandshakeMessageT message) {
        LOGGER.debug("Adjusting context for extensions");
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                ExtensionHandler handler =
                    HandlerFactory.getExtensionHandler(tlsContext, extension.getExtensionTypeConstant());
                handler.adjustTLSContext(extension);

            }
        }
    }

    @Override
    public void prepareAfterParse(HandshakeMessageT message) {
        super.prepareAfterParse(message);

        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = message.getHandshakeMessageType();

                ExtensionHandler extensionHandler =
                    HandlerFactory.getExtensionHandler(tlsContext, extensionMessage.getExtensionTypeConstant());

                if (extensionMessage instanceof EncryptedServerNameIndicationExtensionMessage) {
                    EncryptedServerNameIndicationExtensionPreparator preparator =
                        (EncryptedServerNameIndicationExtensionPreparator) extensionHandler
                            .getPreparator(extensionMessage);
                    if (message instanceof ClientHelloMessage) {
                        preparator.setClientHelloMessage((ClientHelloMessage) message);
                    }
                    preparator.prepareAfterParse();
                }
            }
        }
    }

    @Override
    public abstract HandshakeMessageParser<HandshakeMessageT> getParser(byte[] message, int pointer);

    @Override
    public abstract HandshakeMessagePreparator<HandshakeMessageT> getPreparator(HandshakeMessageT message);

    @Override
    public abstract HandshakeMessageSerializer<HandshakeMessageT> getSerializer(HandshakeMessageT message);
}
