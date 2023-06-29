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

import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TimeoutDelegateTest extends AbstractDelegateTest<TimeoutDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new TimeoutDelegate());
    }

    /** Test of getTimeout method, of class TimeoutDelegate. */
    @Test
    public void testGetTimeout() {
        args = new String[2];
        args[0] = "-timeout";
        args[1] = "123";
        assertNull(delegate.getTimeout());
        jcommander.parse(args);
        assertEquals(123, (int) delegate.getTimeout());
    }

    /** Test of setTimeout method, of class TimeoutDelegate. */
    @Test
    public void testSetTimeout() {
        assertNull(delegate.getTimeout());
        delegate.setTimeout(123);
        assertEquals(123, (int) delegate.getTimeout());
    }

    /** Test of applyDelegate method, of class TimeoutDelegate. */
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

        assertEquals(expectedTimeout, config.getDefaultClientConnection().getTimeout().intValue());
        assertEquals(expectedTimeout, config.getDefaultServerConnection().getTimeout().intValue());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2)); // little
        // ugly
    }
}
