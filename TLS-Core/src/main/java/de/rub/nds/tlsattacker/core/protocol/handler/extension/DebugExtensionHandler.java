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
import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;

public class DebugExtensionHandler extends ExtensionHandler<DebugExtensionMessage> {

    public DebugExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(DebugExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getConnectionEndType()) {
            tlsContext.setReadDebugContent(message.getDebugContent().getValue());
        } else {
            tlsContext.setWriteDebugContent(message.getDebugContent().getValue());
        }
    }
}
