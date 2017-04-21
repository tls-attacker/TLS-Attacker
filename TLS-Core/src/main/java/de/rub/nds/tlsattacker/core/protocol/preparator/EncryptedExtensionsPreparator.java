/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class EncryptedExtensionsPreparator extends HandshakeMessagePreparator<EncryptedExtensionsMessage> {

    private final EncryptedExtensionsMessage msg;

    public EncryptedExtensionsPreparator(TlsContext context, EncryptedExtensionsMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        prepareExtensions();
        prepareExtensionLength();
    }

}