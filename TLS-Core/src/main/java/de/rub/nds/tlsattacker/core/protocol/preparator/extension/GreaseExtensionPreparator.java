/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GreaseExtensionPreparator extends ExtensionPreparator<GreaseExtensionMessage> {
    public GreaseExtensionPreparator(Chooser chooser, GreaseExtensionMessage message,
            ExtensionSerializer<GreaseExtensionMessage> serializer) {
        super(chooser, message, serializer);
    }

    @Override
    public void prepareExtensionContent() {

    }
}
