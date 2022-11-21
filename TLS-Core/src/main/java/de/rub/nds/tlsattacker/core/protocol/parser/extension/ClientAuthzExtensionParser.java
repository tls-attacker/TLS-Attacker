/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;

public class ClientAuthzExtensionParser extends ExtensionParser<ClientAuthzExtensionMessage> {

    public ClientAuthzExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(ClientAuthzExtensionMessage msg) {
        msg.setAuthzFormatListLength(parseIntField(ExtensionByteLength.CLIENT_AUTHZ_FORMAT_LIST_LENGTH));
        msg.setAuthzFormatList(parseByteArrayField(msg.getAuthzFormatListLength().getValue()));
    }

    @Override
    protected ClientAuthzExtensionMessage createExtensionMessage() {
        return new ClientAuthzExtensionMessage();
    }

}
