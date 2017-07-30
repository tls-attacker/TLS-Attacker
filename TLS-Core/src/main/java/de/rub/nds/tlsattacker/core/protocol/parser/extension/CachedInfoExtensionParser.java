/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedInfoExtensionParser extends ExtensionParser<CachedInfoExtensionMessage> {

    private List<CachedObject> cachedObjectList;
    private TlsContext context;

    public CachedInfoExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(CachedInfoExtensionMessage msg) {
        context = new TlsContext();
        msg.setCachedInfoLength(parseIntField(ExtensionByteLength.CACHED_INFO_LENGTH));
        msg.setCachedInfoBytes(parseByteArrayField(msg.getCachedInfoLength().getValue()));

        int position = 0;
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        cachedObjectList = new LinkedList<>();

        // since there are only 2 cached information types, there can only be a
        // list with 2 of them.
        if (msg.getCachedInfoLength().getValue() <= 2) {
            context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        }

        while (position < msg.getCachedInfoLength().getValue()) {
            CachedObjectParser parser = new CachedObjectParser(position, msg.getCachedInfoBytes().getValue(), context);
            cachedObjectList.add(parser.parse());
            position = parser.getPointer();
        }
        msg.setCachedInfo(cachedObjectList);
    }

    @Override
    protected CachedInfoExtensionMessage createExtensionMessage() {
        return new CachedInfoExtensionMessage();
    }

}
