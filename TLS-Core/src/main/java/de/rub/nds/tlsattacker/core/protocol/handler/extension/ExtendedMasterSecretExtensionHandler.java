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
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ExtendedMasterSecretExtensionHandler extends ExtensionHandler<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtendedMasterSecretExtensionParser getParser(byte[] message, int pointer) {
        return new ExtendedMasterSecretExtensionParser(pointer, message);
    }

    @Override
    public ExtendedMasterSecretExtensionPreparator getPreparator(ExtendedMasterSecretExtensionMessage message) {
        return new ExtendedMasterSecretExtensionPreparator(context, message, getSerializer(message));
    }

    @Override
    public ExtendedMasterSecretExtensionSerializer getSerializer(ExtendedMasterSecretExtensionMessage message) {
        return new ExtendedMasterSecretExtensionSerializer(message);
    }

    /**
     * Adjusts the TlsContext.
     *
     * @param message
     */
    @Override
    public void adjustTLSContext(ExtendedMasterSecretExtensionMessage message) {
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER
                || context.getConfig().isEnforceSettings()) {
            context.setIsExtendedMasterSecretExtension(true);
        }
    }

}
