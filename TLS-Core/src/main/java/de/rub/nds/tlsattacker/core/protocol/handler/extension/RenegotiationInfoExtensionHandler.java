/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RenegotiationInfoExtensionHandler extends ExtensionHandler<RenegotiationInfoExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RenegotiationInfoExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(RenegotiationInfoExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The RenegotiationInfo length shouldn't exceed 2 bytes as defined in RFC 5246. " + "Length was "
                + message.getExtensionLength().getValue());
        }
        if (context.getTalkingConnectionEndType() != context.getChooser().getConnectionEndType()) {
            context.setRenegotiationInfo(message.getRenegotiationInfo().getValue());
            LOGGER.debug("The context RenegotiationInfo was set to "
                + ArrayConverter.bytesToHexString(message.getRenegotiationInfo()));
        }
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            if (message.getRenegotiationInfo().getValue().length == 1
                && message.getRenegotiationInfo().getValue()[0] == 0) {
                context.setSecureRenegotiation(true);
            }
        }

    }

}
