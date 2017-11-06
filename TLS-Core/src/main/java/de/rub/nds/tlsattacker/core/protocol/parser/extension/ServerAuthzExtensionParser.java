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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;

public class ServerAuthzExtensionParser extends ExtensionParser<ServerAuthzExtensionMessage> {

    public ServerAuthzExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(ServerAuthzExtensionMessage msg) {
        msg.setAuthzFormatListLength(parseIntField(ExtensionByteLength.SERVER_AUTHZ_FORMAT_LIST_LENGTH));
        msg.setAuthzFormatList(parseByteArrayField(msg.getAuthzFormatListLength().getValue()));
    }

    @Override
    protected ServerAuthzExtensionMessage createExtensionMessage() {
        return new ServerAuthzExtensionMessage();
    }

}
