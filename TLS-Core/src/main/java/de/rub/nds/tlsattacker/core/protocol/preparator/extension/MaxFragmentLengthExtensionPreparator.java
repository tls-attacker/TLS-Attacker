/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MaxFragmentLengthExtensionPreparator extends ExtensionPreparator<MaxFragmentLengthExtensionMessage> {

    private final MaxFragmentLengthExtensionMessage message;

    public MaxFragmentLengthExtensionPreparator(Chooser chooser, MaxFragmentLengthExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing MaxFragmentLengthExtensionMessage");
        message.setMaxFragmentLength(chooser.getConfig().getMaxFragmentLength().getArrayValue());
    }

}
