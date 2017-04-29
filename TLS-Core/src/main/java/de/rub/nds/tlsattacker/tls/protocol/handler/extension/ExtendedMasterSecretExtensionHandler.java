/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

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
        LOGGER.debug("The extended master secret handler returned the extended " + "master secret extension parser.");
        return new ExtendedMasterSecretExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(ExtendedMasterSecretExtensionMessage message) {
        LOGGER.debug("The extended master secret handler returned the extended "
                + "master secret extension preparator.");
        return new ExtendedMasterSecretExtensionPreparator(context, message);
    }

    @Override
    public ExtensionSerializer getSerializer(ExtendedMasterSecretExtensionMessage message) {
        LOGGER.debug("The extended master secret handler returned the extended "
                + "master secret extension serializer.");
        return new ExtendedMasterSecretExtensionSerializer(message);
    }

    /**
     * Adjusts the TlsContext.
     *
     * @param message
     */
    @Override
    public void adjustTLSContext(ExtendedMasterSecretExtensionMessage message) {
        context.setIsExtendedMasterSecret(true);
    }

}
