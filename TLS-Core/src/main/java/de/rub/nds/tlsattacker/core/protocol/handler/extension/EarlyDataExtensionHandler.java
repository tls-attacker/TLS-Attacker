/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EarlyDataExtensionHandler extends ExtensionHandler<EarlyDataExtensionMessage> {

    public EarlyDataExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(EarlyDataExtensionMessage message) {
        if (message.getMaxEarlyDataSize() != null) {
            context.setMaxEarlyDataSize(message.getMaxEarlyDataSize().getValue());
        } else if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            context.addNegotiatedExtension(ExtensionType.EARLY_DATA); // client
            // indicated
            // early
            // data
        }
    }

}
