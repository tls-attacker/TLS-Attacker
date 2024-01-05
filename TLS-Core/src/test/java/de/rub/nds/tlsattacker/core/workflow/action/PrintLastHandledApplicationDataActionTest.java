/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.junit.jupiter.api.Test;

public class PrintLastHandledApplicationDataActionTest
        extends AbstractActionTest<PrintLastHandledApplicationDataAction> {
    private final String expectedAppDataEncodedString = "GET /theTestData";

    public PrintLastHandledApplicationDataActionTest() {
        super(
                new PrintLastHandledApplicationDataAction(),
                PrintLastHandledApplicationDataAction.class);
        TlsContext context = state.getTlsContext();
        context.setLastHandledApplicationMessageData(expectedAppDataEncodedString.getBytes());
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        String expectedAppDataHexString = "\n47 45 54 20 2F 74 68 65  54 65 73 74 44 61 74 61";
        assertEquals(action.getLastHandledApplicationData(), expectedAppDataHexString);
    }

    @Test
    public void testExecuteWithAsciiEncodingSavesAscii() throws Exception {
        action.setStringEncoding("US-ASCII");
        super.testExecute();
        assertEquals(expectedAppDataEncodedString, action.getLastHandledApplicationData());
        assertTrue(action.executedAsPlanned());
    }
}
