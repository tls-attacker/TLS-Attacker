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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ServerAuthzExtensionHandler extends ExtensionHandler<ServerAuthzExtensionMessage> {

    public ServerAuthzExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(ServerAuthzExtensionMessage message) {
        context.setServerAuthzDataFormatList(AuthzDataFormat.byteArrayToList(message.getAuthzFormatList().getValue()));
    }

}
