/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**

 */

// todo implement SupplementalDataMessagePreparator
public class SupplementalDataMessagePreparator<T extends SupplementalDataMessage> extends
        HandshakeMessagePreparator<HandshakeMessage> {

    private final SupplementalDataMessage msg;

    public SupplementalDataMessagePreparator(Chooser chooser, SupplementalDataMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing SupplementalDataMessage");
        throw new UnsupportedOperationException("Not Implemented");
    }

}
