/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.AlpnExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class AlpnExtensionHandler extends ExtensionHandler<AlpnExtensionMessage> {

    public AlpnExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public AlpnExtensionParser getParser(byte[] message, int pointer) {
        return new AlpnExtensionParser(pointer, message);
    }

    @Override
    public AlpnExtensionPreparator getPreparator(AlpnExtensionMessage message) {
        return new AlpnExtensionPreparator(context, message);
    }

    @Override
    public AlpnExtensionSerializer getSerializer(AlpnExtensionMessage message) {
        return new AlpnExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(AlpnExtensionMessage message) {
        context.setApplicationLayerProtocolNegotiationAnnouncedProtocols(message.getAlpnAnnouncedProtocols().getValue());
        LOGGER.debug("Adjustet the TLS context application layer protocol negotiation announced protocols to "
                + ArrayConverter.bytesToHexString(message.getAlpnAnnouncedProtocols()));
    }

}
