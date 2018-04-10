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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ServerDelegateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private ServerDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new ServerDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getPort method, of class ServerDelegate.
     */
    @Test
    public void testGetPort() {
        args = new String[2];
        args[0] = "-port";
        args[1] = "1234";
        assertTrue(delegate.getPort() == null);
        jcommander.parse(args);
        assertTrue(delegate.getPort() == 1234);
    }

    /**
     * Test of setPort method, of class ServerDelegate.
     */
    @Test
    public void testSetPort() {
        assertTrue(delegate.getPort() == null);
        delegate.setPort(1234);
        assertTrue(delegate.getPort() == 1234);
    }

    /**
     * Test of applyDelegate method, of class ServerDelegate.
     */
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
        assertThat(actual.getPort(), equalTo(1234));
        assertThat(actual.getLocalConnectionEndType(), equalTo(ConnectionEndType.SERVER));
        assertThat(actual.getTimeout(), equalTo(expectedDefaultTimeout));

    }

    /**
     * Make sure that applying with port = null fails properly.
     */
    @Test
    public void applyingEmptyDelegateThrowsException() {
        Config config = Config.createConfig();
        exception.expect(ParameterException.class);
        exception.expectMessage("Port must be set, but was not specified");
        delegate.applyDelegate(config);
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
        assertThat(actual.getPort(), equalTo(expectedPort));
    }

    @Test
    @Ignore
    /**
     * TODO: Does this test make sense? Rebuild
     */
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        List<String> excludeFields = new LinkedList<>();
        excludeFields.add("keyStore");
        excludeFields.add("ourCertificate");
        // If the server delegate is chosen we change the connection end
        excludeFields.add("connectionEnd");
        // little ugly todo
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, excludeFields));
    }
}
