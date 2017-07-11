/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class EncryptThenMacExtensionPreparator extends ExtensionPreparator<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionPreparator(TlsContext context, EncryptThenMacExtensionMessage message) {
        super(context, message);
    }

    @Override
    public void prepareExtensionContent() {
        // Nothing to prepare here, since it's an opt-in extension
    }

}
