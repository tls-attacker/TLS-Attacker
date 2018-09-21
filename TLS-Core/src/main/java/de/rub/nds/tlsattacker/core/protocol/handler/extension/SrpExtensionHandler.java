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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SRPExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SRPExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SRPExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpExtensionHandler extends ExtensionHandler<SRPExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SrpExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public SRPExtensionParser getParser(byte[] message, int pointer) {
        return new SRPExtensionParser(pointer, message);
    }

    @Override
    public SRPExtensionPreparator getPreparator(SRPExtensionMessage message) {
        return new SRPExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public SRPExtensionSerializer getSerializer(SRPExtensionMessage message) {
        return new SRPExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(SRPExtensionMessage message) {
        context.setSecureRemotePasswordExtensionIdentifier(message.getSrpIdentifier().getValue());
        LOGGER.debug("Adjusted the TLSContext secure remote password extension identifier to "
                + ArrayConverter.bytesToHexString(context.getSecureRemotePasswordExtensionIdentifier()));
    }

}
