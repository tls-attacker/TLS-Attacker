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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
public class ClientDelegateTest {

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
        config.setHost(null);
        args = new String[2];
        args[0] = "-connect";
        args[1] = "123456";

        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getHost().equals("123456"));
        assertTrue(config.getConnectionEndType() == ConnectionEndType.CLIENT);
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        List<String> excludeFields = new LinkedList<>();
        excludeFields.add("ourCertificate");
        excludeFields.add("keyStore");
        excludeFields.add("myConnectionEndType"); // If the client delegate is
        // chosen
        // we change the conntection end
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, excludeFields));// little
                                                                                   // ugly
    }

}
