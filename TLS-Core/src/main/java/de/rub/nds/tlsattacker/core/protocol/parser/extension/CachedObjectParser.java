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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedObjectParser extends Parser<CachedObject> {

    private CachedObject cachedObject;
    private final TlsContext context;

    public CachedObjectParser(int startposition, byte[] array, TlsContext context) {
        super(startposition, array);
        this.context = context;
    }

    @Override
    public CachedObject parse() {
        cachedObject = new CachedObject();

        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
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
