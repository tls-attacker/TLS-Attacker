/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.mitm.main;

import static de.rub.nds.tlsattacker.util.FileHelper.getResourceAsString;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class TlsMitmCommonUsageTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsMitmCommonUsageTest.class.getName());

    @Category(IntegrationTests.class)
    @Test
    public void showHelp() {
        String expected = getResourceAsString(this.getClass(), "/mitm_stdout_help.txt");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream console = System.out;

        try {
            System.setOut(new PrintStream(bytes));
            (new TlsMitm("-help")).run();
        } finally {
            System.setOut(console);
        }

        assertEquals(expected, bytes.toString());
    }

    @Test
    @Ignore("Implement me...")
    public void writeAndReloadTrace() {
    }
}
