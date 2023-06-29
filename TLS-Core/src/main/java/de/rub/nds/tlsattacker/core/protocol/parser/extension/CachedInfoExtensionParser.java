/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class CachedInfoExtensionParser extends ExtensionParser<CachedInfoExtensionMessage> {

    private List<CachedObject> cachedObjectList;

    public CachedInfoExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(CachedInfoExtensionMessage msg) {
        cachedObjectList = new LinkedList<>();
        msg.setCachedInfoLength(parseIntField(ExtensionByteLength.CACHED_INFO_LENGTH));
        byte[] cachedInfoBytes = parseByteArrayField(msg.getCachedInfoLength().getValue());
        msg.setCachedInfoBytes(cachedInfoBytes);
        ByteArrayInputStream innerStream = new ByteArrayInputStream(cachedInfoBytes);
        ConnectionEndType connectionEndType = getTlsContext().getTalkingConnectionEndType();

        while (innerStream.available() > 0) {
            CachedObjectParser parser = new CachedObjectParser(innerStream, connectionEndType);
            CachedObject object = new CachedObject();
            parser.parse(object);
            cachedObjectList.add(object);
        }
        msg.setCachedInfo(cachedObjectList);
    }
}
