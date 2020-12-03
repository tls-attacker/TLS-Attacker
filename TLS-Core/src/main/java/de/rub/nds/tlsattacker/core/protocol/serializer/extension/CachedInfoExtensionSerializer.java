/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;

public class CachedInfoExtensionSerializer extends ExtensionSerializer<CachedInfoExtensionMessage> {

    private final CachedInfoExtensionMessage msg;

    public CachedInfoExtensionSerializer(CachedInfoExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getCachedInfoLength().getValue(), ExtensionByteLength.CACHED_INFO_LENGTH);
        appendBytes(msg.getCachedInfoBytes().getValue());

        return getAlreadySerialized();
    }

}
