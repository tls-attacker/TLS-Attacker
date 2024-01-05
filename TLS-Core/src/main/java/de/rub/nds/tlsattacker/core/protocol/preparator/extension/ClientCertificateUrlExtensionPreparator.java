/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientCertificateUrlExtensionPreparator
        extends ExtensionPreparator<ClientCertificateUrlExtensionMessage> {

    public ClientCertificateUrlExtensionPreparator(
            Chooser chooser, ClientCertificateUrlExtensionMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareExtensionContent() {
        // nothing to prepare here, since it's an opt-in extension
    }
}
