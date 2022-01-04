/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

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
