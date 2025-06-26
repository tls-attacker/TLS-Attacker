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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class VerifyDelegateTest extends AbstractDelegateTest<VerifyDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new VerifyDelegate());
    }

    @Test
    public void testGetVerifyDepth() {
        assertNull(delegate.getVerifyDepth());
    }

    @Test
    public void testSetVerifyDepth() {
        delegate.setVerifyDepth(1);
        assertEquals(1, delegate.getVerifyDepth());
        delegate.setVerifyDepth(5);
        assertEquals(5, delegate.getVerifyDepth());
        delegate.setVerifyDepth(null);
        assertNull(delegate.getVerifyDepth());
    }

    @Test
    public void testApplyDelegateWithDepthSet() {
        Config config = Config.createConfig();
        assertFalse(config.isClientAuthentication());

        delegate.setVerifyDepth(1);
        delegate.applyDelegate(config);
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testApplyDelegateWithNullDepth() {
        Config config = Config.createConfig();
        assertFalse(config.isClientAuthentication());

        delegate.setVerifyDepth(null);
        delegate.applyDelegate(config);
        assertFalse(config.isClientAuthentication());
    }

    @Test
    public void testParseWithUpperCaseVerify() {
        String[] args = new String[2];
        args[0] = "-Verify";
        args[1] = "1";
        jcommander.parse(args);
        assertEquals(1, delegate.getVerifyDepth());
    }

    @Test
    public void testParseWithLowerCaseVerify() {
        String[] args = new String[2];
        args[0] = "-verify";
        args[1] = "3";
        jcommander.parse(args);
        assertEquals(3, delegate.getVerifyDepth());
    }

    @Test
    public void testParseWithInvalidNumber() {
        String[] args = new String[2];
        args[0] = "-Verify";
        args[1] = "not_a_number";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    @Test
    public void testParseWithNegativeNumber() {
        String[] args = new String[2];
        args[0] = "-Verify";
        args[1] = "-1";
        jcommander.parse(args);
        assertEquals(-1, delegate.getVerifyDepth());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        boolean originalClientAuth = config.isClientAuthentication();
        delegate.applyDelegate(config);
        assertEquals(originalClientAuth, config.isClientAuthentication());
    }
}
