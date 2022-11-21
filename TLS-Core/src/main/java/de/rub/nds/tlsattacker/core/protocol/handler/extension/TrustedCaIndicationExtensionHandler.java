/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedCaIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedCaIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class TrustedCaIndicationExtensionHandler extends ExtensionHandler<TrustedCaIndicationExtensionMessage> {

    public TrustedCaIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public TrustedCaIndicationExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new TrustedCaIndicationExtensionParser(pointer, message, config);
    }

    @Override
    public TrustedCaIndicationExtensionPreparator getPreparator(TrustedCaIndicationExtensionMessage message) {
        return new TrustedCaIndicationExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public TrustedCaIndicationExtensionSerializer getSerializer(TrustedCaIndicationExtensionMessage message) {
        return new TrustedCaIndicationExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(TrustedCaIndicationExtensionMessage message) {
        context.setTrustedCaIndicationExtensionCas(message.getTrustedAuthorities());
    }

}
