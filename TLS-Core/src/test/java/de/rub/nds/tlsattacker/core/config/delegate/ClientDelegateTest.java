/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ClientDelegateTest extends AbstractDelegateTest<ClientDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new ClientDelegate());
    }

    /** Test of getHost method, of class ClientDelegate. */
    @Test
    public void testGetHost() {
        args = new String[2];
        args[0] = "-connect";
        args[1] = "127.0.1.1";
        assertNull(delegate.getHost());
        jcommander.parse(args);
        assertEquals("127.0.1.1", delegate.getHost());
    }

    /** Test of setHost method, of class ClientDelegate. */
    @Test
    public void testSetHost() {
        assertNull(delegate.getHost());
        delegate.setHost("123456");
        assertEquals("123456", delegate.getHost());
    }

    @Test
    public void testApplyDelegateNullHost() {
        Config config = Config.createConfig();
        ParameterException exception =
                assertThrows(ParameterException.class, () -> delegate.applyDelegate(config));
        assertEquals("Could not parse provided host: null", exception.getMessage());
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
        assertEquals(expectedHostname, actual.getHostname());
    }

    /**
     * Provides test vectors with localhost as host for {@link #testHostIsAsExpected(String, String,
     * int)} in the format of (providedUrl, expectedHost, expectedPort).
     */
    public static Stream<Arguments> provideHostTestVectorsWithLocalhost() {
        return Stream.of(
                Arguments.of("localhost", "localhost", 443),
                Arguments.of("localhost:123", "localhost", 123),
                Arguments.of("localhost:123/", "localhost", 123),
                Arguments.of("localhost:123/test.php", "localhost", 123),
                Arguments.of("localhost:123/test.php?a=b", "localhost", 123),
                Arguments.of("localhost:123/test.php?a=b#", "localhost", 123),
                Arguments.of("http://localhost", "localhost", 443),
                Arguments.of("http://localhost:123", "localhost", 123),
                Arguments.of("http://localhost:123/", "localhost", 123),
                Arguments.of("http://localhost:123/test.php", "localhost", 123),
                Arguments.of("http://localhost:123/test.php?a=b", "localhost", 123),
                Arguments.of("http://localhost:123/test.php?a=b#", "localhost", 123),
                Arguments.of("https://localhost", "localhost", 443),
                Arguments.of("https://localhost:123", "localhost", 123),
                Arguments.of("https://localhost:123/", "localhost", 123),
                Arguments.of("https://localhost:123/test.php", "localhost", 123),
                Arguments.of("https://localhost:123/test.php?a=b", "localhost", 123),
                Arguments.of("https://localhost:123/test.php?a=b#", "localhost", 123));
    }

    /**
     * Provides test vectors with DNS hostname as host for {@link
     * #testHostIsAsExpectedWithDns(String, String, int)} in the format of (providedUrl,
     * expectedHost, expectedPort).
     */
    public static Stream<Arguments> provideHostTestVectorsWithDns() {
        return Stream.of(
                Arguments.of("hackmanit.de", "hackmanit.de", 443),
                Arguments.of("hackmanit.de:123", "hackmanit.de", 123),
                Arguments.of("hackmanit.de:123/", "hackmanit.de", 123),
                Arguments.of("hackmanit.de:123/test.php", "hackmanit.de", 123),
                Arguments.of("hackmanit.de:123/test.php?a=b", "hackmanit.de", 123),
                Arguments.of("hackmanit.de:123/test.php?a=b#", "hackmanit.de", 123),
                Arguments.of("http://hackmanit.de", "hackmanit.de", 443),
                Arguments.of("http://hackmanit.de:123", "hackmanit.de", 123),
                Arguments.of("http://hackmanit.de:123/", "hackmanit.de", 123),
                Arguments.of("http://hackmanit.de:123/test.php", "hackmanit.de", 123),
                Arguments.of("http://hackmanit.de:123/test.php?a=b", "hackmanit.de", 123),
                Arguments.of("http://hackmanit.de:123/test.php?a=b#", "hackmanit.de", 123),
                Arguments.of("https://hackmanit.de", "hackmanit.de", 443),
                Arguments.of("https://hackmanit.de:123", "hackmanit.de", 123),
                Arguments.of("https://hackmanit.de:123/", "hackmanit.de", 123),
                Arguments.of("https://hackmanit.de:123/test.php", "hackmanit.de", 123),
                Arguments.of("https://hackmanit.de:123/test.php?a=b", "hackmanit.de", 123),
                Arguments.of("https://hackmanit.de:123/test.php?a=b#", "hackmanit.de", 123));
    }

    @ParameterizedTest
    @MethodSource("provideHostTestVectorsWithLocalhost")
    public void testHostIsAsExpected(String providedUrl, String expectedHost, int expectedPort) {
        assertHostIsAsExpected(providedUrl, expectedHost, expectedPort);
    }

    @ParameterizedTest
    @MethodSource("provideHostTestVectorsWithDns")
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testHostIsAsExpectedWithDns(
            String providedUrl, String expectedHost, int expectedPort) {
        assertHostIsAsExpected(providedUrl, expectedHost, expectedPort);
    }

    private void assertHostIsAsExpected(String providedUrl, String expectedHost, int expectedPort) {
        delegate.setHost(providedUrl);
        Config config = Config.createConfig();
        delegate.applyDelegate(config);
        OutboundConnection defaultClientConnection = config.getDefaultClientConnection();
        assertEquals(expectedHost, defaultClientConnection.getHostname());
        assertEquals(expectedPort, defaultClientConnection.getPort().intValue());
        assertSame(ConnectionEndType.CLIENT, defaultClientConnection.getLocalConnectionEndType());
    }
}
