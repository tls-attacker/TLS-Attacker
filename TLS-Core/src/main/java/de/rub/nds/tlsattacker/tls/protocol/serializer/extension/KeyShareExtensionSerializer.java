/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionSerializer extends ExtensionSerializer<KeyShareExtensionMessage> {

    private final KeyShareExtensionMessage message;
    private final boolean isServer;

    public KeyShareExtensionSerializer(KeyShareExtensionMessage message, boolean isServer) {
        super(message);
        this.message = message;
        this.isServer = isServer;
    }

    @Override
    public byte[] serializeExtensionContent() {
        if (isServer != true) {
            appendInt(message.getKeyShareListLength().getValue(), ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        }
        appendBytes(message.getKeyShareListBytes().getValue());
        return getAlreadySerialized();
    }
}
