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
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SupportedVersionsExtensionMessage;

/**
 * @author Nurullah Erinola
 */
public class SupportedVersionsExtensionSerializer extends ExtensionSerializer<SupportedVersionsExtensionMessage> {

    private final SupportedVersionsExtensionMessage message;

    public SupportedVersionsExtensionSerializer(SupportedVersionsExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getSupportedVersionsLength().getValue(),
                ExtensionByteLength.SUPPORTED_PROTOCOL_VERSIONS_LENGTH);
        appendBytes(message.getSupportedVersions().getValue());
        return getAlreadySerialized();
    }
}