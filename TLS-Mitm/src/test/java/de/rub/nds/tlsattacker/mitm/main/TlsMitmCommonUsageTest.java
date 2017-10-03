/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.mitm.main;

import static de.rub.nds.tlsattacker.util.FileHelper.getResourceAsString;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class TlsMitmCommonUsageTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsMitmCommonUsageTest.class.getName());

    @Test
    @Category(IntegrationTests.class)
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

        assertThat(bytes.toString(), equalTo(expected));
    }

    @Test
    @Ignore("Implement me...")
    public void writeAndReloadTrace() {
    }
}
