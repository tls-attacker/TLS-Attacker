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

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedObjectParser extends Parser<CachedObject> {

    private CachedObject cachedObject;
    private final boolean isClientState;

    public CachedObjectParser(int startposition, byte[] array, boolean isClientState) {
        super(startposition, array);
        this.isClientState = isClientState;
    }

    @Override
    public CachedObject parse() {
        cachedObject = new CachedObject();

        if (isClientState) {
            cachedObject.setCachedInformationType(parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValueLength(parseIntField(ExtensionByteLength.CACHED_INFO_HASH_LENGTH));
            cachedObject.setHashValue(parseByteArrayField(cachedObject.getHashValueLength().getValue()));
            cachedObject.setIsClientState(isClientState);
        } else {
            cachedObject.setCachedInformationType(parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValue((ModifiableByteArray) null);
            cachedObject.setHashValueLength((ModifiableInteger) null);
            cachedObject.setIsClientState(isClientState);
        }

        return cachedObject;
    }

}
