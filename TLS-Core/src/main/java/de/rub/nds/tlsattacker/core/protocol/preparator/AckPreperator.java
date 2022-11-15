/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckPreperator extends ProtocolMessagePreparator<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckPreperator(Chooser chooser, AckMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing AckMessage");
        prepareRecordNumbers();
    }

    private void prepareRecordNumbers() {
        message.setRecordNumbers(createRecordNumberArray());
    }

    private byte[] createRecordNumberArray() {
        // TODO
        return new byte[] {};
    }
}
