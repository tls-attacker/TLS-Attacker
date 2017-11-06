/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBException;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *

 */
public class TlsConfigIOTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testReadWriteRead() throws IOException, JAXBException {
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

    /**
     * Verify that a single custom connection end can be loaded properly from
     * XML.
     * 
     * @throws IOException
     * @throws JAXBException
     */
    @Test
    public void testReadCustomConnectionEnd() throws IOException, JAXBException {
        InputStream stream = Config.class.getResourceAsStream("/test_config_custom_connection_end.xml");

        ClientConnectionEnd expected = new ClientConnectionEnd("testConnectionEnd", 8002, "testHostname");

        Config config = Config.createConfig(stream);
        assertNotNull(config);
        ConnectionEnd conEnd = config.getConnectionEnd();
        assertNotNull(conEnd);
        assertTrue(conEnd.equals(expected));
    }

    /**
     * Verify that multiple connection ends can be loaded properly from XML.
     * 
     * @throws IOException
     * @throws JAXBException
     */
    @Test
    public void testReadMultiConnectionEnds() throws IOException, JAXBException {
        InputStream stream = Config.class.getResourceAsStream("/test_config_multiple_connection_ends.xml");

        List<ConnectionEnd> expected = new ArrayList<>();
        expected.add(new ClientConnectionEnd("conEnd1", 1111, "host1111"));
        expected.add(new ServerConnectionEnd("conEnd2", 4444));
        expected.add(new ClientConnectionEnd("conEnd3", 2222, "host2222"));

        Config config = Config.createConfig(stream);
        assertNotNull(config);
        List<ConnectionEnd> conEnds = config.getConnectionEnds();
        assertFalse(conEnds.isEmpty());
        assertTrue(conEnds.equals(expected));
    }
}
