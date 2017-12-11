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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import java.util.Objects;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class MaxFragmentLengthDelegateTest {

    private MaxFragmentLengthDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new MaxFragmentLengthDelegate();
        this.jcommander = new JCommander(delegate);

    }

    /**
     * Test of getMaxFragmentLength method, of class MaxFragmentLengthDelegate.
     */
    @Test
    public void testGetMaxFragmentLength() {
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "4";
        assertTrue(delegate.getMaxFragmentLength() == null);
        jcommander.parse(args);
        assertTrue(delegate.getMaxFragmentLength() == 4);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidMaxFragmentLength() {
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "lelele";
        jcommander.parse(args);
    }

    /**
     * Test of setMaxFragmentLength method, of class MaxFragmentLengthDelegate.
     */
    @Test
    public void testSetMaxFragmentLength() {
        assertFalse(Objects.equals(delegate.getMaxFragmentLength(), 4));
        delegate.setMaxFragmentLength(4);
        assertTrue(Objects.equals(delegate.getMaxFragmentLength(), 4));
    }

    /**
     * Test of applyDelegate method, of class MaxFragmentLengthDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-max_fragment_length";
        args[1] = "4";
        assertFalse(config.getMaxFragmentLength() == MaxFragmentLength.TWO_12);
        assertFalse(config.isAddMaxFragmentLengthExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isAddMaxFragmentLengthExtension());
        assertTrue(config.getMaxFragmentLength() == MaxFragmentLength.TWO_12);
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
