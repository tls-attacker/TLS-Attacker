/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import org.junit.jupiter.api.Test;

public class AlertPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<AlertMessage, AlertPreparator> {

    public AlertPreparatorTest() {
        super(AlertMessage::new, AlertPreparator::new);
    }

    /** Test of prepareProtocolMessageContents method, of class AlertPreparator. */
    @Test
    @Override
    public void testPrepare() {
        message.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        preparator.prepare();
        assertEquals(AlertLevel.FATAL.getValue(), (byte) message.getLevel().getValue());
        assertEquals(
                AlertDescription.DECRYPT_ERROR.getValue(),
                (byte) message.getDescription().getValue());
    }

    @Test
    public void testPrepareFromDefaultConfig() {
        context.getConfig().setDefaultAlertDescription(AlertDescription.BAD_CERTIFICATE);
        context.getConfig().setDefaultAlertLevel(AlertLevel.FATAL);
        preparator.prepare();
        assertEquals(
                AlertDescription.BAD_CERTIFICATE.getValue(),
                (byte) message.getDescription().getValue());
        assertEquals(AlertLevel.FATAL.getValue(), (byte) message.getLevel().getValue());
    }
}
