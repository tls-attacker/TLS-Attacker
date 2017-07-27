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
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedObjectSerializer extends Serializer<CachedObject> {

    private final CachedObject object;

    public CachedObjectSerializer(CachedObject object) {
        this.object = object;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(object.getCachedInformationType().getValue());
        if (object.getHashValueLength().getValue() != null) {
            appendInt(object.getHashValueLength().getValue(), ExtensionByteLength.CACHED_INFO_HASH_LENGTH);

        }
        if (object.getHashValue().getValue() != null) {
            appendBytes(object.getHashValue().getValue());

        }

        return getAlreadySerialized();
    }

}
