/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;

public class ClientAuthzExtensionHandler extends ExtensionHandler<ClientAuthzExtensionMessage> {

    public ClientAuthzExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ClientAuthzExtensionMessage message) {
        tlsContext.setClientAuthzDataFormatList(
                AuthzDataFormat.byteArrayToList(message.getAuthzFormatList().getValue()));
    }
}
