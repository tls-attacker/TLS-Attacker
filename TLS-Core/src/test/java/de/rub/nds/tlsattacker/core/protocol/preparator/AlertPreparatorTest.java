/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class AlertPreparatorTest {

    private AlertMessage message;
    private TlsContext context;
    private AlertPreparator preparator;

    public AlertPreparatorTest() {
    }

    @Before
    public void setUp() {
        message = new AlertMessage();
        context = new TlsContext();
        preparator = new AlertPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class AlertPreparator.
     */
    @Test
    public void testPrepare() {
        message.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        preparator.prepare();
        assertTrue(message.getLevel().getValue() == AlertLevel.FATAL.getValue());
        assertTrue(message.getDescription().getValue() == AlertDescription.DECRYPT_ERROR.getValue());
    }

    @Test
    public void testPrepareFromDefaultConfig() {
        context.getConfig().setDefaultAlertDescription(AlertDescription.BAD_CERTIFICATE);
        context.getConfig().setDefaultAlertLevel(AlertLevel.FATAL);
        preparator.prepare();
        assertTrue(message.getDescription().getValue() == AlertDescription.BAD_CERTIFICATE.getValue());
        assertTrue(message.getLevel().getValue() == AlertLevel.FATAL.getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
