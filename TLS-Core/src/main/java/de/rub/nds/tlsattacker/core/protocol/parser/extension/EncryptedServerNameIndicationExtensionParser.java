/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;

public class EncryptedServerNameIndicationExtensionParser extends
        ExtensionParser<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedServerNameIndicationExtensionParser(int startposition, byte[] array) {

        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(EncryptedServerNameIndicationExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 0) {
            parseNonce(msg);
        } else {
            LOGGER.debug("Received empty ESNI Extension");
        }

    }

    @Override
    protected EncryptedServerNameIndicationExtensionMessage createExtensionMessage() {
        return new EncryptedServerNameIndicationExtensionMessage();
    }

    private void parseNonce(EncryptedServerNameIndicationExtensionMessage msg) {
        byte[] nonce = parseByteArrayField(ExtensionByteLength.NONCE);
        msg.setServerEsniNonce(nonce);
        LOGGER.info("Received Nonce: " + ArrayConverter.bytesToHexString(nonce));
    }
}
