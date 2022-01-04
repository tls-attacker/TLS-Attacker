/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ExtendedMasterSecretExtensionHandler extends ExtensionHandler<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtendedMasterSecretExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new ExtendedMasterSecretExtensionParser(pointer, message, config);
    }

    @Override
    public ExtendedMasterSecretExtensionPreparator getPreparator(ExtendedMasterSecretExtensionMessage message) {
        return new ExtendedMasterSecretExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtendedMasterSecretExtensionSerializer getSerializer(ExtendedMasterSecretExtensionMessage message) {
        return new ExtendedMasterSecretExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(ExtendedMasterSecretExtensionMessage message) {
        if (context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET)
            && context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET)) {
            context.setUseExtendedMasterSecret(true);
        }
    }

}
