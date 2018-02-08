/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import org.junit.Test;

public class ClientCommandConfigTest {

    /**
     * Test config command line parsing
     */
    @Test
    public void testCommandLineParsing() {
        JCommander jc = new JCommander(new GeneralDelegate());
        // TODO
        //
        // ServerCommandConfig server = new ServerCommandConfig();
        // jc.addCommand(ServerCommandConfig.COMMAND, server);
        // ClientCommandConfig client = new ClientCommandConfig();
        // jc.addCommand(ClientCommandConfig.COMMAND, client);
        //
        // jc.parse("client", "-connect", "localhost:443", "-keystore",
        // "test.pem", "-password", "password",
        // "-workflow_trace_type", "FULL");
        //
        // assertEquals("client", jc.getParsedCommand());
        // assertEquals("localhost:443", client.getConnect());
        // assertEquals("test.pem", client.getKeystore());
        // assertEquals("password", client.getPassword());
    }

    /**
     * Test invalid config without connect parameter
     */
    @Test(expected = ParameterException.class)
    public void testInvalidCommandLineParsing() {
        JCommander jc = new JCommander();

        ClientCommandConfig client = new ClientCommandConfig(new GeneralDelegate());
        jc.addCommand(ClientCommandConfig.COMMAND, client);

        jc.parse("client", "-connect");
    }
}
