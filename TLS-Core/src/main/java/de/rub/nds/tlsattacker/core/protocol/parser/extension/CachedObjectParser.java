/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;

public class CachedObjectParser extends Parser<CachedObject> {

    private final ConnectionEndType connectionEndType;

    public CachedObjectParser(InputStream stream, ConnectionEndType connectionEndType) {
        super(stream);
        this.connectionEndType = connectionEndType;
    }

    @Override
    public void parse(CachedObject cachedObject) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            cachedObject.setCachedInformationType(
                    parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValueLength(
                    parseIntField(ExtensionByteLength.CACHED_INFO_HASH_LENGTH));
            cachedObject.setHashValue(
                    parseByteArrayField(cachedObject.getHashValueLength().getValue()));
        } else {
            cachedObject.setCachedInformationType(
                    parseByteField(ExtensionByteLength.CACHED_INFO_TYPE));
            cachedObject.setHashValue((ModifiableByteArray) null);
            cachedObject.setHashValueLength((ModifiableInteger) null);
        }
    }
}
