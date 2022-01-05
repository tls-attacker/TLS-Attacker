/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import java.util.Objects;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;

public class RecordSizeLimitDelegateTest {

    private RecordSizeLimitDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new RecordSizeLimitDelegate();
        this.jcommander = new JCommander(delegate);

    }

    /**
     * Test of getRecordSizeLimit method, of class RecordSizeLimitDelegate.
     */
    @Test
    public void testGetRecordSizeLimit() {
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "1337";
        assertTrue(delegate.getRecordSizeLimit() == null);
        jcommander.parse(args);
        assertTrue(delegate.getRecordSizeLimit() == 1337);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidRecordSizeLimit() {
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "abcdefg";
        jcommander.parse(args);
    }

    /**
     * Test of setRecordSizeLimit method, of class RecordSizeLimitDelegate.
     */
    @Test
    public void testSetRecordSizeLimit() {
        assertFalse(Objects.equals(delegate.getRecordSizeLimit(), 1337));
        delegate.setRecordSizeLimit(1337);
        assertTrue(Objects.equals(delegate.getRecordSizeLimit(), 1337));
    }

    /**
     * Test of applyDelegate method, of class RecordSizeLimitDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "1337";
        assertFalse(config.isAddRecordSizeLimitExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isAddRecordSizeLimitExtension());
        assertTrue(config.getInboundRecordSizeLimit() == 1337);
    }

    @Test
    public void testApplyDelegateOutOfLowerBound() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "0";
        assertFalse(config.isAddRecordSizeLimitExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testApplyDelegateOutOfUpperBound() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "65536";
        assertFalse(config.isAddRecordSizeLimitExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testApplyDelegateNegative() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "-1";
        assertFalse(config.isAddRecordSizeLimitExtension());
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertFalse(config.isAddRecordSizeLimitExtension());
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
