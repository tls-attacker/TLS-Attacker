/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.EncryptedExtensionsMessage;

/**
 * @author Nurullah Erinola
 */
public class EncryptedExtensionsParser extends HandshakeMessageParser<EncryptedExtensionsMessage> {
   
    public EncryptedExtensionsParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.ENCRYPTED_EXTENSIONS, version);
    }

    @Override
    protected void parseHandshakeMessageContent(EncryptedExtensionsMessage msg) {
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg);
            }
        }
    }

    @Override
    protected EncryptedExtensionsMessage createHandshakeMessage() {
        return new EncryptedExtensionsMessage();
    }
    
}