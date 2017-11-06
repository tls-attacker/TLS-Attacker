/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TruncatedHmacExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class TruncatedHmacExtensionPreparator extends ExtensionPreparator<TruncatedHmacExtensionMessage> {

    public TruncatedHmacExtensionPreparator(Chooser chooser, TruncatedHmacExtensionMessage message,
            TruncatedHmacExtensionSerializer serializer) {
        super(chooser, message, serializer);
    }

    @Override
    public void prepareExtensionContent() {
        // Nothing to prepare here, since it's an opt-in extension
    }

}
