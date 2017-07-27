/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsConfigIOTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testReadWriteRead() throws IOException {
        File f = folder.newFile();
        Config config = Config.createConfig();
        ConfigIO.write(config, f);
        config = ConfigIO.read(f);
        assertNotNull(config);
    }

    @Test
    public void testIncompleteConfig() {
        InputStream stream = Config.class.getResourceAsStream("/test_config.xml");
        Config config = Config.createConfig(stream);
        assertNotNull(config);
        assertTrue(config.getDefaultClientSupportedCiphersuites().size() == 1);
    }
}
