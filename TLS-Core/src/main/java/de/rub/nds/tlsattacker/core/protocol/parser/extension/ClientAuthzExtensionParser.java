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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import java.io.InputStream;

public class ClientAuthzExtensionParser extends ExtensionParser<ClientAuthzExtensionMessage> {

    public ClientAuthzExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ClientAuthzExtensionMessage msg) {
        msg.setAuthzFormatListLength(
                parseIntField(ExtensionByteLength.CLIENT_AUTHZ_FORMAT_LIST_LENGTH));
        msg.setAuthzFormatList(parseByteArrayField(msg.getAuthzFormatListLength().getValue()));
    }
}
