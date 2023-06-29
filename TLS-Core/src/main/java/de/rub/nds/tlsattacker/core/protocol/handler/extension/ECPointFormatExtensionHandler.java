/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECPointFormatExtensionHandler extends ExtensionHandler<ECPointFormatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECPointFormatExtensionHandler(TlsContext context) {
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
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientPointFormatsList(formatList);
        } else {
            tlsContext.setServerPointFormatsList(formatList);
        }
    }
}
