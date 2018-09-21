/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcPointFormatExtensionHandler extends ExtensionHandler<ECPointFormatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcPointFormatExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(ECPointFormatExtensionMessage message) {
        List<ECPointFormat> formatList = new LinkedList<>();
        byte[] pointFormats = message.getPointFormats().getValue();
        for (byte b : pointFormats) {
            ECPointFormat format = ECPointFormat.getECPointFormat(b);
            if (format != null) {
                formatList.add(format);
            } else {
                LOGGER.warn("Unknown ECPointFormat:" + b);
            }
        }
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            context.setClientPointFormatsList(formatList);
        } else {
            context.setServerPointFormatsList(formatList);
        }
    }

    @Override
    public ECPointFormatExtensionParser getParser(byte[] message, int pointer) {
        return new ECPointFormatExtensionParser(pointer, message);
    }

    @Override
    public ECPointFormatExtensionPreparator getPreparator(ECPointFormatExtensionMessage message) {
        return new ECPointFormatExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ECPointFormatExtensionSerializer getSerializer(ECPointFormatExtensionMessage message) {
        return new ECPointFormatExtensionSerializer(message);
    }

}
