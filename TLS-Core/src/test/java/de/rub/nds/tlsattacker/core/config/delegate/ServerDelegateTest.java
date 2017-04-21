/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerDelegateTest {

    private ServerDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public ServerDelegateTest() {
    }

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
        TlsConfig config = TlsConfig.createConfig();
        config.setServerPort(1);
        args = new String[2];
        args[0] = "-port";
        args[1] = "1234";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getServerPort() == 1234);
        assertTrue(config.getConnectionEnd() == ConnectionEnd.SERVER);
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        List<String> excludeFields = new LinkedList<>();
        excludeFields.add("keyStore");
        excludeFields.add("connectionEnd"); // If the server delegate is
                                            // chosen
                                            // we change the conntection end
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, excludeFields));// little
                                                                                   // ugly
                                                                                   // todo
    }
}
