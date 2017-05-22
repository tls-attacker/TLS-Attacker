/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class EncryptedExtensionsMessage extends HandshakeMessage {

    public EncryptedExtensionsMessage() {
        super(HandshakeMessageType.ENCRYPTED_EXTENSIONS);
    }

    public EncryptedExtensionsMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Extensions: ");
        if (getExtensions() == null) {
            sb.append("null");
        } else {
            for (ExtensionMessage e : getExtensions()) {
                sb.append(e.toString());
            }
        }
        return sb.toString();
    }

    @Override
    public EncryptedExtensionsHandler getHandler(TlsContext context) {
        return new EncryptedExtensionsHandler(context);
    }

}