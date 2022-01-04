/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TrustedCaIndicationExtensionHandler extends ExtensionHandler<TrustedCaIndicationExtensionMessage> {

    public TrustedCaIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(TrustedCaIndicationExtensionMessage message) {
        context.setTrustedCaIndicationExtensionCas(message.getTrustedAuthorities());
    }

}
