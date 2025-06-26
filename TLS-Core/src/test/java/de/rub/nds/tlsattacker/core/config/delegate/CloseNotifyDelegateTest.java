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

public class CloseNotifyDelegateTest extends AbstractDelegateTest<CloseNotifyDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new CloseNotifyDelegate());
    }

    /** Test of getFinishWithCloseNotify method, of class CloseNotifyDelegate. */
    @Test
    public void testGetFinishWithCloseNotify() {
        args = new String[2];
        args[0] = "-close_notify";
        args[1] = "true";
        assertNull(delegate.getFinishWithCloseNotify());
        jcommander.parse(args);
        assertEquals(true, delegate.getFinishWithCloseNotify());
    }

    /** Test of setFinishWithCloseNotify method, of class CloseNotifyDelegate. */
    @Test
    public void testSetFinishWithCloseNotify() {
        assertNull(delegate.getFinishWithCloseNotify());
        delegate.setFinishWithCloseNotify(true);
        assertEquals(true, delegate.getFinishWithCloseNotify());
    }

    /** Test of applyDelegate method, of class CloseNotifyDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = new Config();
        // Default value should be false
        assertFalse(config.isFinishWithCloseNotify());

        args = new String[2];
        args[0] = "-close_notify";
        args[1] = "true";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertTrue(config.isFinishWithCloseNotify());
    }

    @Test
    public void testApplyDelegateFalse() {
        Config config = new Config();
        config.setFinishWithCloseNotify(true);
        assertTrue(config.isFinishWithCloseNotify());

        args = new String[2];
        args[0] = "-close_notify";
        args[1] = "false";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertFalse(config.isFinishWithCloseNotify());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = new Config();
        Config config2 = new Config();
        delegate.applyDelegate(config);
        assertTrue(
                EqualsBuilder.reflectionEquals(
                        config, config2, "certificateChainConfig")); // little ugly
    }
}
