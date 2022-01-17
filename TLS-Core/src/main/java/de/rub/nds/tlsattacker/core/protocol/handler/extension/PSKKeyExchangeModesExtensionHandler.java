/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import java.util.LinkedList;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PSKKeyExchangeModesExtensionHandler extends ExtensionHandler<PSKKeyExchangeModesExtensionMessage> {

    public PSKKeyExchangeModesExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(PSKKeyExchangeModesExtensionMessage message) {
        if (message.getKeyExchangeModesListBytes() != null) {
            adjustKeyExchangeModes(message);
        }
    }

    private void adjustKeyExchangeModes(PSKKeyExchangeModesExtensionMessage message) {
        context.setClientPskKeyExchangeModes(new LinkedList<PskKeyExchangeMode>());
        for (byte exchangeModeByte : message.getKeyExchangeModesListBytes().getValue()) {
            PskKeyExchangeMode mode = PskKeyExchangeMode.getExchangeMode(exchangeModeByte);
            context.getClientPskKeyExchangeModes().add(mode);
        }
    }

}
