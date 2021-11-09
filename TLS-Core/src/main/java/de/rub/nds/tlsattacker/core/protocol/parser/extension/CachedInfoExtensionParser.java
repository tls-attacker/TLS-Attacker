/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class CachedInfoExtensionParser extends ExtensionParser<CachedInfoExtensionMessage> {

    private List<CachedObject> cachedObjectList;

    public CachedInfoExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    @Override
    public void parseExtensionMessageContent(CachedInfoExtensionMessage msg) {
        msg.setCachedInfoLength(parseIntField(ExtensionByteLength.CACHED_INFO_LENGTH));
        byte[] cachedInfoBytes = parseByteArrayField(msg.getCachedInfoLength().getValue());
        msg.setCachedInfoBytes(cachedInfoBytes);
        ByteArrayInputStream innerStream = new ByteArrayInputStream(cachedInfoBytes);
        // TODO The parser should know and not guess which connectionEnd it is
        ConnectionEndType connectionEndType = ConnectionEndType.CLIENT;
        cachedObjectList = new LinkedList<>();

        if (msg.getCachedInfoLength().getValue() <= 2) {
            connectionEndType = ConnectionEndType.SERVER;
        }

        while (innerStream.available() > 0) {
            CachedObjectParser parser = new CachedObjectParser(innerStream, connectionEndType);
            cachedObjectList.add(parser.parse());
        }
        msg.setCachedInfo(cachedObjectList);
    }

    @Override
    protected CachedInfoExtensionMessage createExtensionMessage() {
        return new CachedInfoExtensionMessage();
    }

}
