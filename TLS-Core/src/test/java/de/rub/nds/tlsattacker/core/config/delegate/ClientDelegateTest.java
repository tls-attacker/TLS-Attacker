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
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientDelegateTest {

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
        config.clearConnectionEnds();
        args = new String[2];
        args[0] = "-connect";
        args[1] = "99.99.99.99:1337";

        jcommander.parse(args);
        delegate.applyDelegate(config);
        ConnectionEnd newConEnd = config.getConnectionEnd();
        assertNotNull(newConEnd);
        assertTrue(newConEnd.getHostname().equals("99.99.99.99"));
        assertTrue(newConEnd.getPort() == 1337);
        assertTrue(newConEnd.getConnectionEndType() == ConnectionEndType.CLIENT);
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

    /**
     * Make sure that applying this delegate removes all previously known
     * connection ends.
     */
    @Test
    public void testApplyDelegateClearsOldConnectionEnds() {
        Config config = Config.createConfig();
        delegate.setHost("test");
        delegate.applyDelegate(config);
        assertTrue(config.getConnectionEnds().size() == 1);
        // This should pass without ConfigurationException, too.
        ConnectionEnd ourEnd = config.getConnectionEnd();
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
        excludeFields.add("ourCertificate");
        excludeFields.add("keyStore");
        excludeFields.add("connectionEnd");
        // little ugly
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, excludeFields));
    }

}
