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
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TimeoutDelegateTest {

    private TimeoutDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new TimeoutDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getTimeout method, of class TimeoutDelegate.
     */
    @Test
    public void testGetTimeout() {
        args = new String[2];
        args[0] = "-timeout";
        args[1] = "123";
        assertTrue(delegate.getTimeout() == null);
        jcommander.parse(args);
        assertTrue(delegate.getTimeout() == 123);
    }

    /**
     * Test of setTimeout method, of class TimeoutDelegate.
     */
    @Test
    public void testSetTimeout() {
        assertTrue(delegate.getTimeout() == null);
        delegate.setTimeout(123);
        assertTrue(delegate.getTimeout() == 123);
    }

    /**
     * Test of applyDelegate method, of class TimeoutDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.getDefaultClientConnection().setTimeout(1000);
        config.getDefaultServerConnection().setTimeout(1000);
        int expectedTimeout = 123;
        args = new String[2];
        args[0] = "-timeout";
        args[1] = Integer.toString(expectedTimeout);

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertThat(config.getDefaultClientConnection().getTimeout(), equalTo(expectedTimeout));
        assertThat(config.getDefaultServerConnection().getTimeout(), equalTo(expectedTimeout));
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2));// little
        // ugly
    }
}
