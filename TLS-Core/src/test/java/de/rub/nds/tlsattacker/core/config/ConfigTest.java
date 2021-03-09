/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config;

import java.io.File;
import org.junit.Before;
import org.junit.Test;

public class ConfigTest {

    public ConfigTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of createConfig method, of class Config.
     */
    @Test
    public void assertConfigInResourcesIsEqual() {
        ConfigIO.write(new Config(), new File("src/main/resources/default_config.xml"));
    }

}
