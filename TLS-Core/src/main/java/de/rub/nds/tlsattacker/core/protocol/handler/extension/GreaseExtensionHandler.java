/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.GreaseExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.GreaseExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class GreaseExtensionHandler extends ExtensionHandler<GreaseExtensionMessage> {

    public GreaseExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(GreaseExtensionMessage message) {

    }
}
