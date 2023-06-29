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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ServerDelegateTest extends AbstractDelegateTest<ServerDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new ServerDelegate());
    }

    /** Test of getPort method, of class ServerDelegate. */
    @Test
    public void testGetPort() {
        args = new String[2];
        args[0] = "-port";
        args[1] = "1234";
        assertNull(delegate.getPort());
        jcommander.parse(args);
        assertEquals(1234, (int) delegate.getPort());
    }

    /** Test of setPort method, of class ServerDelegate. */
    @Test
    public void testSetPort() {
        assertNull(delegate.getPort());
        delegate.setPort(1234);
        assertEquals(1234, (int) delegate.getPort());
    }

    /** Test of applyDelegate method, of class ServerDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        int expectedDefaultTimeout = 390121;
        config.getDefaultServerConnection().setTimeout(expectedDefaultTimeout);
        args = new String[2];
        args[0] = "-port";
        args[1] = "1234";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        AliasedConnection actual = config.getDefaultServerConnection();
        assertNotNull(actual);
        assertEquals(1234, actual.getPort().intValue());
        assertSame(ConnectionEndType.SERVER, actual.getLocalConnectionEndType());
        assertEquals(expectedDefaultTimeout, actual.getTimeout().intValue());
    }

    /** Make sure that applying with port = null fails properly. */
    @Test
    public void applyingEmptyDelegateThrowsException() {
        Config config = Config.createConfig();
        ParameterException exception =
                assertThrows(ParameterException.class, () -> delegate.applyDelegate(config));
        assertTrue(exception.getMessage().startsWith("Port must be set, but was not specified"));
    }

    @Test
    public void testApplyDelegateWithEmptyConfig() {
        Config config = Config.createConfig();
        config.setDefaultServerConnection(null);
        int expectedPort = 8777;
        delegate.setPort(expectedPort);
        delegate.applyDelegate(config);
        AliasedConnection actual = config.getDefaultServerConnection();
        assertNotNull(actual);
        assertEquals(expectedPort, actual.getPort().intValue());
    }
}
