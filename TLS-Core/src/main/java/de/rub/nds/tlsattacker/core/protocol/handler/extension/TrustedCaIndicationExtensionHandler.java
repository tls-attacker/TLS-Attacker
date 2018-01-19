/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

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
    public TrustedCaIndicationExtensionParser getParser(byte[] message, int pointer) {
        return new TrustedCaIndicationExtensionParser(pointer, message);
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
