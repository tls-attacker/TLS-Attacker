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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class MaxFragmentLengthExtensionPreparator extends ExtensionPreparator<MaxFragmentLengthExtensionMessage> {

    private final MaxFragmentLengthExtensionMessage message;

    public MaxFragmentLengthExtensionPreparator(TlsContext context, MaxFragmentLengthExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing MaxFragmentLengthExtensionMessage");
        message.setMaxFragmentLength(context.getConfig().getMaxFragmentLength().getArrayValue());
    }

}
