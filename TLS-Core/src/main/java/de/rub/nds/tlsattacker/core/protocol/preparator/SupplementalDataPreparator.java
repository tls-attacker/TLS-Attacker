/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * todo implement SupplementalDataPreparator
 */
public class SupplementalDataPreparator extends HandshakeMessagePreparator<SupplementalDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SupplementalDataMessage msg;

    public SupplementalDataPreparator(Chooser chooser, SupplementalDataMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing SupplementalDataMessage");
        throw new UnsupportedOperationException("Not Implemented");
    }

}
