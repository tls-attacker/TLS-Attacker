/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtendedMasterSecretExtensionParser extends ExtensionParser<ExtendedMasterSecretExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedMasterSecretExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    /**
     * Parses the content of the extended master secret extension message. There
     * SHOULDN'T be any data.
     *
     * @param msg
     *            The Message that should be parsed
     */
    @Override
    public void parseExtensionMessageContent(ExtendedMasterSecretExtensionMessage msg) {
        byte[] auxData = parseByteArrayField(msg.getExtensionLength().getValue());
        if (auxData.length > 0) {
            LOGGER.warn("There shouldn't be any data in the body of" + " the extended master secret extension."
                    + "Data send by server: " + ArrayConverter.bytesToHexString(auxData));
        }
    }

    @Override
    protected ExtendedMasterSecretExtensionMessage createExtensionMessage() {
        return new ExtendedMasterSecretExtensionMessage();
    }

}
