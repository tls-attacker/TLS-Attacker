/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedCaIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedCaIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class TrustedCaIndicationExtensionHandler extends ExtensionHandler<TrustedCaIndicationExtensionMessage> {

    public TrustedCaIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(TrustedCaIndicationExtensionMessage message) {
        context.setTrustedCaIndicationExtensionCas(message.getTrustedAuthorities());
    }

}
