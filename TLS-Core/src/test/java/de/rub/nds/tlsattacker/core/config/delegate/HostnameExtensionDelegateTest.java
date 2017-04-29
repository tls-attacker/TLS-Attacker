/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HostnameExtensionDelegateTest {

    private HostnameExtensionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public HostnameExtensionDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new HostnameExtensionDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getSniHostname method, of class HostnameExtensionDelegate.
     */
    @Test
    public void testGetSniHostname() {
        args = new String[2];
        args[0] = "-server_name";
        args[1] = "its_me";
        assertFalse("its_me".equals(delegate.getSniHostname()));
        jcommander.parse(args);
        assertTrue("its_me".equals(delegate.getSniHostname()));
    }

    /**
     * Test of setSniHostname method, of class HostnameExtensionDelegate.
     */
    @Test
    public void testSetSniHostname() {
        assertFalse("123456".equals(delegate.getSniHostname()));
        delegate.setSniHostname("123456");
        assertTrue("123456".equals(delegate.getSniHostname()));
    }

    /**
     * Test of applyDelegate method, of class HostnameExtensionDelegate.
     */
    @Test
    public void testApplyDelegate() {
        args = new String[2];
        args[0] = "-server_name";
        args[1] = "its_me";
        jcommander.parse(args);
        TlsConfig config = TlsConfig.createConfig();
        config.setSniHostname(null);
        config.setAddServerNameIndicationExtension(false);
        assertFalse(config.isAddServerNameIndicationExtension());
        delegate.applyDelegate(config);
        assertTrue(config.getSniHostname().equals("its_me"));
        assertTrue(config.isAddServerNameIndicationExtension());
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
    }
}
