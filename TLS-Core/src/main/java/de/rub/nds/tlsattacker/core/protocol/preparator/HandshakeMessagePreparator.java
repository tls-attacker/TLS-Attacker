/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EncryptedServerNameIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PreSharedKeyExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PreSharedKeyExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The HandshakeMessage that should be prepared
 */
public abstract class HandshakeMessagePreparator<T extends HandshakeMessage> extends TlsMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HandshakeMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    protected void prepareMessageLength(int length) {
        message.setLength(length);
        LOGGER.debug("Length: " + message.getLength().getValue());
    }

    private void prepareMessageType(HandshakeMessageType type) {
        message.setType(type.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    @Override
    protected void prepareProtocolMessageContents() {
        if (chooser.getSelectedProtocolVersion().isDTLS()) {
            message.setMessageSequence(chooser.getContext().getDtlsWriteHandshakeMessageSequence());
        }
        prepareHandshakeMessageContents();

        if (!(message instanceof DtlsHandshakeMessageFragment)) {
            HandshakeMessageHandler<T> handler = message.getHandler(chooser.getContext());
            HandshakeMessageSerializer<T> serializer = handler.getSerializer(message);
            prepareMessageLength(serializer.serializeHandshakeMessageContent().length);
            prepareMessageType(message.getHandshakeMessageType());
        }
    }

    protected abstract void prepareHandshakeMessageContents();

    protected void prepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = message.getHandshakeMessageType();
                if (extensionMessage instanceof KeyShareExtensionMessage && message instanceof ServerHelloMessage) {
                    ServerHelloMessage serverHello = (ServerHelloMessage) message;
                    KeyShareExtensionMessage ksExt = (KeyShareExtensionMessage) extensionMessage;
                    if (serverHello.setRetryRequestModeInKeyShare()) {
                        ksExt.setRetryRequestMode(true);
                    }
                }
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(chooser.getContext(),
                    extensionMessage.getExtensionTypeConstant());
                handler.getPreparator(extensionMessage).prepare();
                try {
                    stream.write(extensionMessage.getExtensionBytes().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                }
            }
        }
        message.setExtensionBytes(stream.toByteArray());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(message.getExtensionBytes().getValue()));
    }

    protected void afterPrepareExtensions() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (message.getExtensions() != null) {
            for (ExtensionMessage extensionMessage : message.getExtensions()) {
                HandshakeMessageType handshakeMessageType = message.getHandshakeMessageType();
                ExtensionHandler handler = HandlerFactory.getExtensionHandler(chooser.getContext(),
                    extensionMessage.getExtensionTypeConstant());
                Preparator preparator = handler.getPreparator(extensionMessage);
                if (handler instanceof PreSharedKeyExtensionHandler && message instanceof ClientHelloMessage
                    && chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                    ((PreSharedKeyExtensionPreparator) preparator).setClientHello((ClientHelloMessage) message);
                    preparator.afterPrepare();
                } else if (handler instanceof EncryptedServerNameIndicationExtensionHandler
                    && message instanceof ClientHelloMessage
                    && chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                    ClientHelloMessage clientHelloMessage = (ClientHelloMessage) message;
                    ((EncryptedServerNameIndicationExtensionPreparator) preparator)
                        .setClientHelloMessage(clientHelloMessage);
                    preparator.afterPrepare();
                }
                if (extensionMessage.getExtensionBytes() != null
                    && extensionMessage.getExtensionBytes().getValue() != null) {
                    try {
                        stream.write(extensionMessage.getExtensionBytes().getValue());
                    } catch (IOException ex) {
                        throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                    }
                } else {
                    LOGGER.debug(
                        "If we are in a SSLv2 or SSLv3 Connection we do not add extensions, as SSL did not contain extensions");
                    LOGGER.debug("If however, the extensions are prepared, we will ad themm");
                }
            }
        }
        message.setExtensionBytes(stream.toByteArray());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(message.getExtensionBytes().getValue()));
    }

    protected void prepareExtensionLength() {
        message.setExtensionsLength(message.getExtensionBytes().getValue().length);
        LOGGER.debug("ExtensionLength: " + message.getExtensionsLength().getValue());
    }
}
