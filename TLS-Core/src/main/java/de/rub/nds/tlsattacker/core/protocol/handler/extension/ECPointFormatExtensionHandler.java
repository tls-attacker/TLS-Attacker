/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

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
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            context.setClientPointFormatsList(formatList);
        } else {
            context.setServerPointFormatsList(formatList);
        }
    }

}
