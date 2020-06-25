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

import static org.junit.Assert.*;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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

    /**
     * Test of the parseKeyShareOld flag of class Config.
     */
    @Test
    public void testParseKeyShareOld() {
        Config config = Config.createConfig();

        // if parseKeyShareOld is true, disable ExtendedRandom
        config.setParseKeyShareOld(true);
        config.setAddKeyShareExtension(true);
        config.setAddExtendedRandomExtension(true);
        assertFalse(config.isAddExtendedRandomExtension());
        assertTrue(config.isAddKeyShareExtension());

        // if parseKeyShareOld false, allow ExtendedRandom
        config.setParseKeyShareOld(false);
        config.setAddKeyShareExtension(true);
        config.setAddExtendedRandomExtension(true);
        assertTrue(config.isAddKeyShareExtension());
        assertTrue(config.isAddExtendedRandomExtension());

        // automatically set parseKeyShareOld to true if certain TLS13 Drafts
        // are supported
        config = Config.createConfig();
        config.setParseKeyShareOld(false);
        config.setSupportedVersions(ProtocolVersion.getOldKeyShareVersions());
        assertTrue(config.isParseKeyShareOld());

        // remove ExtendedRandom when old Key Share Drafts are supported but
        // parseKeyShareOld flag was not set.
        config = Config.createConfig();
        config.setAddKeyShareExtension(true);
        config.setAddExtendedRandomExtension(true);
        config.setSupportedVersions(ProtocolVersion.getOldKeyShareVersions());
        assertTrue(config.isAddKeyShareExtension());
        assertFalse(config.isAddExtendedRandomExtension());
        config.setAddExtendedRandomExtension(true);
        assertFalse(config.isAddExtendedRandomExtension());
        config.setParseKeyShareOld(false);
        config.setAddExtendedRandomExtension(true);
        assertFalse(config.isAddExtendedRandomExtension());

    }

}
