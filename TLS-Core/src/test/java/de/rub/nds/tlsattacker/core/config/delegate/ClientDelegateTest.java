/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

public class ClientDelegateTest {

    private final Logger LOGGER = LogManager.getLogger();

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private ClientDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        delegate = new ClientDelegate();
        jcommander = new JCommander(delegate);
    }

    /**
     * Test of getHost method, of class ClientDelegate.
     */
    @Test
    public void testGetHost() {
        args = new String[2];
        args[0] = "-connect";
        args[1] = "127.0.1.1";
        assertTrue(delegate.getHost() == null);
        jcommander.parse(args);
        assertTrue(delegate.getHost().equals("127.0.1.1"));
    }

    /**
     * Test of setHost method, of class ClientDelegate.
     */
    @Test
    public void testSetHost() {
        assertTrue(delegate.getHost() == null);
        delegate.setHost("123456");
        assertTrue(delegate.getHost().equals("123456"));
    }

    /**
     * Test of applyDelegate method, of class ClientDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-connect";
        args[1] = "99.99.99.99:1448";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        AliasedConnection actual = config.getDefaultClientConnection();
        assertNotNull(actual);
        assertThat(actual.getHostname(), equalTo("99.99.99.99"));
        assertThat(actual.getPort(), equalTo(1448));
        assertThat(actual.getLocalConnectionEndType(), equalTo(ConnectionEndType.CLIENT));
    }

    /**
     * Make sure that applying with host = null fails properly.
     */
    @Test
    public void testApplyDelegateNullHost() {
        Config config = Config.createConfig();
        exception.expect(ParameterException.class);
        exception.expectMessage("Could not parse provided host: null");
        delegate.applyDelegate(config);
    }

    @Test
    public void testApplyDelegateWithEmptyConfig() {
        Config config = Config.createConfig();
        config.setDefaultClientConnection(null);
        String expectedHostname = "testHostname.de";
        delegate.setHost(expectedHostname);
        delegate.applyDelegate(config);
        OutboundConnection actual = config.getDefaultClientConnection();
        assertNotNull(actual);
        // This should pass without ConfigurationException, too.
        assertThat(actual.getHostname(), equalTo(expectedHostname));
    }

    @Test
    public void bulkTest() throws UnknownHostException {
        checkHostIsAsExpected("localhost", InetAddress.getByName("localhost").getHostName(), 443);
        checkHostIsAsExpected("localhost:123", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("localhost:123/", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("localhost:123/test.php", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("localhost:123/test.php?a=b", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("localhost:123/test.php?a=b#", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("http://localhost", InetAddress.getByName("localhost").getHostName(), 443);
        checkHostIsAsExpected("http://localhost:123", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("http://localhost:123/", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("http://localhost:123/test.php", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("http://localhost:123/test.php?a=b", InetAddress.getByName("localhost").getHostName(),
                123);
        checkHostIsAsExpected("http://localhost:123/test.php?a=b#", InetAddress.getByName("localhost").getHostName(),
                123);
        checkHostIsAsExpected("https://localhost", InetAddress.getByName("localhost").getHostName(), 443);
        checkHostIsAsExpected("https://localhost:123", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("https://localhost:123/", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("https://localhost:123/test.php", InetAddress.getByName("localhost").getHostName(), 123);
        checkHostIsAsExpected("https://localhost:123/test.php?a=b", InetAddress.getByName("localhost").getHostName(),
                123);
        checkHostIsAsExpected("https://localhost:123/test.php?a=b#", InetAddress.getByName("localhost").getHostName(),
                123);
        checkHostIsAsExpected("127.0.0.1", InetAddress.getByName("127.0.0.1").getHostName(), 443);
        checkHostIsAsExpected("127.0.0.1:123", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("127.0.0.1:123/", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("127.0.0.1:123/test.php", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("127.0.0.1:123/test.php?a=b", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("127.0.0.1:123/test.php?a=b#", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("http://127.0.0.1", InetAddress.getByName("127.0.0.1").getHostName(), 443);
        checkHostIsAsExpected("http://127.0.0.1:123", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("http://127.0.0.1:123/", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("http://127.0.0.1:123/test.php", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("http://127.0.0.1:123/test.php?a=b", InetAddress.getByName("127.0.0.1").getHostName(),
                123);
        checkHostIsAsExpected("http://127.0.0.1:123/test.php?a=b#", InetAddress.getByName("127.0.0.1").getHostName(),
                123);
        checkHostIsAsExpected("https://127.0.0.1", InetAddress.getByName("127.0.0.1").getHostName(), 443);
        checkHostIsAsExpected("https://127.0.0.1:123", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("https://127.0.0.1:123/", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("https://127.0.0.1:123/test.php", InetAddress.getByName("127.0.0.1").getHostName(), 123);
        checkHostIsAsExpected("https://127.0.0.1:123/test.php?a=b", InetAddress.getByName("127.0.0.1").getHostName(),
                123);
        checkHostIsAsExpected("https://127.0.0.1:123/test.php?a=b#", InetAddress.getByName("127.0.0.1").getHostName(),
                123);
    }

    @Test
    @Ignore("No good testcase available atm")
    public void reverseDnsTest() {
        try {
            InetAddress address = InetAddress.getByName("hackmanit.de");
            checkHostIsAsExpected(address.getHostAddress(), "hackmanit.de", 443);
        } catch (UnknownHostException ex) {
            LOGGER.error("Could not perform reverse dns test. This can happen if you try to build offline", ex);
        }
    }

    @Test
    @Category(IntegrationTests.class)
    public void testDnsDelegate() throws UnknownHostException {
        checkHostIsAsExpected("hackmanit.de", InetAddress.getByName("hackmanit.de").getHostName(), 443);
        checkHostIsAsExpected("hackmanit.de:123", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("hackmanit.de:123/", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("hackmanit.de:123/test.php", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("hackmanit.de:123/test.php?a=b", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("hackmanit.de:123/test.php?a=b#", InetAddress.getByName("hackmanit.de").getHostName(),
                123);
        checkHostIsAsExpected("http://hackmanit.de", InetAddress.getByName("hackmanit.de").getHostName(), 443);
        checkHostIsAsExpected("http://hackmanit.de:123", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("http://hackmanit.de:123/", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("http://hackmanit.de:123/test.php", InetAddress.getByName("hackmanit.de").getHostName(),
                123);
        checkHostIsAsExpected("http://hackmanit.de:123/test.php?a=b", InetAddress.getByName("hackmanit.de")
                .getHostName(), 123);
        checkHostIsAsExpected("http://hackmanit.de:123/test.php?a=b#", InetAddress.getByName("hackmanit.de")
                .getHostName(), 123);
        checkHostIsAsExpected("https://hackmanit.de", InetAddress.getByName("hackmanit.de").getHostName(), 443);
        checkHostIsAsExpected("https://hackmanit.de:123", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("https://hackmanit.de:123/", InetAddress.getByName("hackmanit.de").getHostName(), 123);
        checkHostIsAsExpected("https://hackmanit.de:123/test.php", InetAddress.getByName("hackmanit.de").getHostName(),
                123);
        checkHostIsAsExpected("https://hackmanit.de:123/test.php?a=b", InetAddress.getByName("hackmanit.de")
                .getHostName(), 123);
        checkHostIsAsExpected("https://hackmanit.de:123/test.php?a=b#", InetAddress.getByName("hackmanit.de")
                .getHostName(), 123);

    }

    private void checkHostIsAsExpected(String fullhost, String host, int port) {
        delegate.setHost(fullhost);
        Config config = Config.createConfig();
        delegate.applyDelegate(config);
        OutboundConnection defaultClientConnection = config.getDefaultClientConnection();
        assertThat(defaultClientConnection.getHostname(), equalTo(host));
        assertThat(defaultClientConnection.getPort(), equalTo(port));
        assertThat(defaultClientConnection.getLocalConnectionEndType(), equalTo(ConnectionEndType.CLIENT));

    }
}
