/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ClientAuthzExtensionHandler extends ExtensionHandler<ClientAuthzExtensionMessage> {

    public ClientAuthzExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(ClientAuthzExtensionMessage message) {
        context.setClientAuthzDataFormatList(AuthzDataFormat.byteArrayToList(message.getAuthzFormatList().getValue()));
    }

}
