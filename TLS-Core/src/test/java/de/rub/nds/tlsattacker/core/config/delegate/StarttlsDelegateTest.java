/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class StarttlsDelegateTest extends AbstractDelegateTest<StarttlsDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new StarttlsDelegate());
    }

    /** Test of getStarttlsType method, of class StarttlsDelegate. */
    @Test
    public void testGetStarttlsType() {
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";
        delegate.setStarttlsType(null);
        assertNotSame(StarttlsType.NONE, delegate.getStarttlsType());
        jcommander.parse(args);
        assertSame(StarttlsType.POP3, delegate.getStarttlsType());
    }

    /** Test of setStarttlsType method, of class StarttlsDelegate. */
    @Test
    public void testSetStarttlsType() {
        assertSame(StarttlsType.NONE, delegate.getStarttlsType());
        delegate.setStarttlsType(StarttlsType.POP3);
        assertSame(StarttlsType.POP3, delegate.getStarttlsType());
    }

    /** Test of applyDelegate method, of class StarttlsDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.POP3, config.getStarttlsType());
    }

    /** -starttls FTP must select the generic STARTTLS layer stack. */
    @Test
    public void testApplyDelegateFtp() {
        Config config = new Config();
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.FTP, config.getStarttlsType());
        assertSame(
                StackConfiguration.GENERIC_OPPORTUNISTIC_TLS,
                config.getDefaultLayerConfiguration());
    }

    /**
     * A STARTTLS upgrade must not toggle the global stop-after-unexpected flag. A refused upgrade
     * (e.g. FTP 4xx/5xx instead of 234) is aborted by the ReceiveRegexAsciiAction itself when the
     * reply can no longer match, so the global flag stays at its default and the subsequent TLS
     * handshake keeps its normal, permissive receive behavior for scanning.
     */
    @Test
    public void testApplyDelegateFtpLeavesGlobalStopTraceFlagUntouched() {
        Config config = new Config();
        args = new String[] {"-starttls", "FTP"};

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertFalse(config.isStopTraceAfterUnexpected());
    }

    /** Without STARTTLS the stop-after-unexpected flag keeps its default (off). */
    @Test
    public void testApplyDelegateNoneLeavesStopTraceDefault() {
        Config config = new Config();
        delegate.setStarttlsType(StarttlsType.NONE);

        delegate.applyDelegate(config);

        assertSame(StarttlsType.NONE, config.getStarttlsType());
        assertFalse(config.isStopTraceAfterUnexpected());
    }
}
