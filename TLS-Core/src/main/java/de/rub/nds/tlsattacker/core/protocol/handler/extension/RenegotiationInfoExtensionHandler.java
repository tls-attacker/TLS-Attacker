/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RenegotiationInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionHandler extends ExtensionHandler<RenegotiationInfoExtensionMessage> {

    public RenegotiationInfoExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public RenegotiationInfoExtensionParser getParser(byte[] message, int pointer) {
        LOGGER.debug("The remegotiation extension handler returned the parser.");
        return new RenegotiationInfoExtensionParser(pointer, message);
    }

    @Override
    public RenegotiationInfoExtensionPreparator getPreparator(RenegotiationInfoExtensionMessage message) {
        LOGGER.debug("The renegotiation info extension handler returned the preparator.");
        return new RenegotiationInfoExtensionPreparator(context, message);
    }

    @Override
    public RenegotiationInfoExtensionSerializer getSerializer(RenegotiationInfoExtensionMessage message) {
        LOGGER.debug("The renegotiatoin info extension handler returned the serializer.");
        return new RenegotiationInfoExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(RenegotiationInfoExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The RenegotiationInfo length shouldn't exceed 2 bytes as defined in RFC 5246. "
                    + "Length was " + message.getExtensionLength().getValue());
        }
        context.setRenegotiationInfo(message.getRenegotiationInfo().getValue());
        LOGGER.debug("The renegotiation info extension handler adjusted the TLS context.");
    }

}
