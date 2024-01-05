/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class TlsConfigIOTest {

    @Test
    public void testReadWriteRead(@TempDir File tempDir) {
        File f = new File(tempDir, "read_write_test.config");
        Config config = Config.createConfig();
        ConfigIO.write(config, f);
        config = ConfigIO.read(f);
        assertNotNull(config);
    }

    @Test
    public void testEmptyConfig() throws IOException {
        try (InputStream stream = Config.class.getResourceAsStream("/test_empty_config.xml")) {
            IllegalArgumentException exception =
                    assertThrows(IllegalArgumentException.class, () -> Config.createConfig(stream));
            assertTrue(exception.getMessage().startsWith("Stream cannot be null"));
        }
    }

    @Test
    public void testIncompleteConfig() throws IOException {
        Config config;
        try (InputStream stream = Config.class.getResourceAsStream("/test_incomplete_config.xml")) {
            config = Config.createConfig(stream);
        }
        assertNotNull(config);
        assertEquals(1, config.getDefaultClientSupportedCipherSuites().size());
    }

    @Test
    public void testReadCustomClientConnection() throws IOException {
        OutboundConnection expected =
                new OutboundConnection("testConnection", 8002, "testHostname");

        Config config;
        try (InputStream stream =
                Config.class.getResourceAsStream("/test_config_custom_client_connection.xml")) {
            config = Config.createConfig(stream);
        }
        assertNotNull(config);

        OutboundConnection con = config.getDefaultClientConnection();
        assertNotNull(con);
        assertEquals(expected, con);
    }

    @Test
    public void testReadCustomServerConnection() throws IOException {
        Config config;
        try (InputStream stream =
                Config.class.getResourceAsStream("/test_config_custom_server_connection.xml")) {
            config = Config.createConfig(stream);
        }
        assertNotNull(config);

        InboundConnection expected = new InboundConnection("testConnection", 8004);
        InboundConnection con = config.getDefaultServerConnection();
        assertNotNull(con);
        assertEquals(expected, con);
    }
}
