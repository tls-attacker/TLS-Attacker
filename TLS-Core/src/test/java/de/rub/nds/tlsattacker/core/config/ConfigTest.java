/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
     * Updates the default_config.xml
     */
    @Test
    public void assertConfigInResourcesIsEqual() {
        ConfigIO.write(new Config(), new File("src/main/resources/default_config.xml"));
    }

}
