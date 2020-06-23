/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This Class handles the Extended Random Extension as defined as in
 * https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionHandler extends ExtensionHandler<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedRandomExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtendedRandomExtensionParser getParser(byte[] message, int pointer) {
        return new ExtendedRandomExtensionParser(pointer, message);
    }

    @Override
    public ExtendedRandomExtensionPreparator getPreparator(ExtendedRandomExtensionMessage message) {
        return new ExtendedRandomExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtendedRandomExtensionSerializer getSerializer(ExtendedRandomExtensionMessage message) {
        return new ExtendedRandomExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(ExtendedRandomExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SessionTLS ticket length shouldn't exceed 2 bytes as defined in Extended Random Draft. "
                    + "Length was " + message.getExtensionLength().getValue());
        }

        if (context.getTalkingConnectionEndType().equals(ConnectionEndType.SERVER)) {
            context.setServerExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug("The context server extended Random was set to "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom()));

        }
        if (context.getTalkingConnectionEndType().equals(ConnectionEndType.CLIENT)) {
            context.setClientExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug("The context client extended Random was set to "
                    + ArrayConverter.bytesToHexString(message.getExtendedRandom()));

        }

    }
}
