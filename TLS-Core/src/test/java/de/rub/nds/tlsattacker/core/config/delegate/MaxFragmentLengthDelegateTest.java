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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MaxFragmentLengthDelegateTest extends AbstractDelegateTest<MaxFragmentLengthDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new MaxFragmentLengthDelegate());
    }

    /** Test of getMaxFragmentLength method, of class MaxFragmentLengthDelegate. */
    @Test
    public void testGetMaxFragmentLength() {
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "4";
        assertNull(delegate.getMaxFragmentLength());
        jcommander.parse(args);
        assertEquals(4, (int) delegate.getMaxFragmentLength());
    }

    @Test
    public void testGetInvalidMaxFragmentLength() {
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "lelele";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setMaxFragmentLength method, of class MaxFragmentLengthDelegate. */
    @Test
    public void testSetMaxFragmentLength() {
        assertNull(delegate.getMaxFragmentLength());
        delegate.setMaxFragmentLength(4);
        assertEquals(4, (int) delegate.getMaxFragmentLength());
    }

    /** Test of applyDelegate method, of class MaxFragmentLengthDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "3";
        assertNotSame(MaxFragmentLength.TWO_11, config.getDefaultMaxFragmentLength());
        assertFalse(config.isAddMaxFragmentLengthExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isAddMaxFragmentLengthExtension());
        assertSame(MaxFragmentLength.TWO_11, config.getDefaultMaxFragmentLength());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
