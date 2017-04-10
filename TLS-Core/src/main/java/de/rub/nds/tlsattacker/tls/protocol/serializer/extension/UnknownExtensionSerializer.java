/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.UnknownExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionSerializer extends ExtensionSerializer<UnknownExtensionMessage> {

    private final UnknownExtensionMessage message;

    public UnknownExtensionSerializer(UnknownExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        if (message.getExtensionData() != null) {
            appendBytes(message.getExtensionData().getValue());
        }
        return getAlreadySerialized();
    }
}
