/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ExtendedMasterSecretExtensionHandler extends ExtensionHandler<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        LOGGER.debug("The extended master secret extension handler returned the parser.");
        return new ExtendedMasterSecretExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(ExtendedMasterSecretExtensionMessage message) {
        LOGGER.debug("The extended master secret extension handler returned the preparator.");
        return new ExtendedMasterSecretExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(ExtendedMasterSecretExtensionMessage message) {
        LOGGER.debug("The extended master secret extension handler returned the serializer.");
        return new ExtendedMasterSecretExtensionSerializer(message);
    }

    /**
     * Adjusts the TlsContext.
     *
     * @param message
     */
    @Override
    public void adjustTLSContext(ExtendedMasterSecretExtensionMessage message) {
        context.setIsExtendedMasterSecretExtension(true);
        LOGGER.debug("The extended master secret extension handler adjusted the TLS context.");
    }

}
