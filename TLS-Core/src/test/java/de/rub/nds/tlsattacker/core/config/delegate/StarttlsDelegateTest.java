/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
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
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(StarttlsType.POP3, config.getStarttlsType());
    }
}
