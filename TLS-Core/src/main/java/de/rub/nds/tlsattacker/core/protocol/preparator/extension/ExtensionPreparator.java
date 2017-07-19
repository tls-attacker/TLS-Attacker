/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ExtensionPreparator<T extends ExtensionMessage> extends Preparator<T> {

    private final ExtensionMessage msg;
    private byte[] content;
    private final ExtensionSerializer<T> serializer;

    public ExtensionPreparator(TlsContext context, T message, ExtensionSerializer<T> serializer) {
        super(context, message);
        this.msg = message;
        this.serializer = serializer;
    }

    @Override
    public final void prepare() {
        prepareExtensionType(msg);
        prepareExtensionContent();
        content = serializer.serializeExtensionContent();
        prepareExtensionLength(msg);
        prepareExtensionBytes(msg);
    }

    public abstract void prepareExtensionContent();

    private void prepareExtensionType(ExtensionMessage msg) {
        msg.setExtensionType(msg.getExtensionTypeConstant().getValue());
        LOGGER.debug("ExtensionType: " + ArrayConverter.bytesToHexString(msg.getExtensionType().getValue()));
    }

    private void prepareExtensionLength(ExtensionMessage msg) {
        msg.setExtensionLength(content.length);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionLength().getValue());
    }

    private void prepareExtensionBytes(ExtensionMessage msg) {
        msg.setExtensionBytes(serializer.serialize());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

}
