/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ExtensionPreparator<T extends ExtensionMessage> extends Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private ExtensionMessage message;

    public ExtensionPreparator(TlsContext context, T message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public final void prepare() {
        prepareExtensionContent();
        ExtensionSerializer serializer = message.getHandler(context).getSerializer(message);
        byte[] content = serializer.serializeExtensionContent();
        message.setExtensionBytes(content);
        message.setExtensionLength(message.getExtensionBytes().getValue().length);
    }

    public abstract void prepareExtensionContent();

}
