/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.server.config;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ServerCommandConfigTest {

    private ServerCommandConfig serverCommandConfig;
    private JCommander jcommander;

    @BeforeEach
    public void setUp() {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        serverCommandConfig = new ServerCommandConfig(generalDelegate);
        jcommander =
                JCommander.newBuilder()
                        .addCommand(ServerCommandConfig.COMMAND, serverCommandConfig)
                        .build();
    }

    @Test
    public void testClientAuthenticationFlag() {
        String[] args = new String[] {"server", "-client_authentication"};
        jcommander.parse(args);

        Config config = serverCommandConfig.createConfig();
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testVerifyFlag() {
        String[] args = new String[] {"server", "-Verify", "1"};
        jcommander.parse(args);

        Config config = serverCommandConfig.createConfig();
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testVerifyFlagLowerCase() {
        String[] args = new String[] {"server", "-verify", "3"};
        jcommander.parse(args);

        Config config = serverCommandConfig.createConfig();
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testBothClientAuthAndVerifyFlags() {
        String[] args = new String[] {"server", "-client_authentication", "-Verify", "2"};
        jcommander.parse(args);

        Config config = serverCommandConfig.createConfig();
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testNoClientAuthFlags() {
        String[] args = new String[] {"server"};
        jcommander.parse(args);

        Config config = serverCommandConfig.createConfig();
        assertFalse(config.isClientAuthentication());
    }

    @Test
    public void testInvalidVerifyValue() {
        String[] args = new String[] {"server", "-Verify", "invalid"};
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }
}
