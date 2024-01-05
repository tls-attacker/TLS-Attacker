/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.client.config;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ClientCommandConfigTest {

    /** Test config command line parsing */
    @Test
    @Disabled("Not implemented")
    public void testCommandLineParsing() {}

    /** Test invalid config without connect parameter */
    @Test
    public void testInvalidCommandLineParsing() {
        JCommander jc = new JCommander();

        ClientCommandConfig client = new ClientCommandConfig(new GeneralDelegate());
        jc.addCommand(ClientCommandConfig.COMMAND, client);

        assertThrows(ParameterException.class, () -> jc.parse("client", "-connect"));
    }
}
