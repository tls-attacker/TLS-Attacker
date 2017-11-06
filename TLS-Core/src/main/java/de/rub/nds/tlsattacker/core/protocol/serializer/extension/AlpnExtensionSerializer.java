/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;

public class AlpnExtensionSerializer extends ExtensionSerializer<AlpnExtensionMessage> {

    private final AlpnExtensionMessage message;

    public AlpnExtensionSerializer(AlpnExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getAlpnExtensionLength().getValue(), ExtensionByteLength.ALPN_EXTENSION_LENGTH);
        appendBytes(message.getAlpnAnnouncedProtocols().getValue());

        return getAlreadySerialized();
    }

}
