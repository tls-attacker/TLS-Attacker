/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

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
        TlsConfig config = TlsConfig.createConfig();
        TlsConfigIO.write(config, f);
        config = TlsConfigIO.read(f);
        assertNotNull(config);
    }

    @Test
    public void testIncompleteConfig() {
        InputStream stream = TlsConfig.class.getResourceAsStream("/test_config.xml");
        TlsConfig config = TlsConfig.createConfig(stream);
        assertNotNull(config);
        assertNotNull(config.getAlias());
        assertTrue(config.getSupportedCiphersuites().size() == 1);
    }
}
