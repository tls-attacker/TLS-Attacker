/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ConnectionIdExtensionMessage;

public class ConnectionIdExtensionHandler extends ExtensionHandler<ConnectionIdExtensionMessage> {

    public ConnectionIdExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ConnectionIdExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getConnectionEndType()) {
            tlsContext.setReadConnectionId(message.getConnectionId().getValue());
        } else {
            tlsContext.setWriteConnectionId(message.getConnectionId().getValue());
        }
    }
}
