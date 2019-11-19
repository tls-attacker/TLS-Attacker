/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;

public class EncryptedServerNameIndicationExtensionSerializer extends
        ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedServerNameIndicationExtensionSerializer(EncryptedServerNameIndicationExtensionMessage message) {
        super(message);
        LOGGER.warn("EncryptedServerNameIndicationExtensionSerializer called. - ESNI implemented yet");
        // TODO Auto-generated constructor stub
    }

    @Override
    public byte[] serializeExtensionContent() {
        // TODO Auto-generated method stub
        // appendBigInteger(BigInteger i, int length)
        // appendInt(int i, int length)
        // appendByte(byte b)
        // appendBytes(byte[] bytes)
        return getAlreadySerialized();
    }

}
