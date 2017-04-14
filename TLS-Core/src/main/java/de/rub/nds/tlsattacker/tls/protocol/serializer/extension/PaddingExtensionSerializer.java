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
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionSerializer extends ExtensionSerializer<PaddingExtensionMessage>{
    
    private final PaddingExtensionMessage message;

    public PaddingExtensionSerializer(PaddingExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getPaddingLength().getValue(), ExtensionByteLength.PADDING_LENGTH);
        appendBytes(message.getPaddingBytes().getValue());
        return getAlreadySerialized();
    }
    
    
}
