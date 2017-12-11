/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class CachedObjectParser extends Parser<CachedObject> {

    private final CachedObject cachedObject;
    private final ConnectionEndType connectionEndType;

    public CachedObjectParser(int startposition, byte[] array, ConnectionEndType connectionEndType) {
        super(startposition, array);
        cachedObject = new CachedObject();
        this.connectionEndType = connectionEndType;
    }

    @Override
    public CachedObject parse() {

        if (connectionEndType == ConnectionEndType.CLIENT) {
            cachedObject.setCachedInformationType(parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValueLength(parseIntField(ExtensionByteLength.CACHED_INFO_HASH_LENGTH));
            cachedObject.setHashValue(parseByteArrayField(cachedObject.getHashValueLength().getValue()));
        } else {
            cachedObject.setCachedInformationType(parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValue((ModifiableByteArray) null);
            cachedObject.setHashValueLength((ModifiableInteger) null);
        }

        return cachedObject;
    }

}
