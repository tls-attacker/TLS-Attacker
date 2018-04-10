/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EarlyDataExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EarlyDataExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EarlyDataExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
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
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new EarlyDataExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(EarlyDataExtensionMessage message) {
        return new EarlyDataExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(EarlyDataExtensionMessage message) {
        return new EarlyDataExtensionSerializer(message);
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
