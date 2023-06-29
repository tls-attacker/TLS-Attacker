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
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordSizeLimitDelegateTest extends AbstractDelegateTest<RecordSizeLimitDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new RecordSizeLimitDelegate());
    }

    /** Test of getRecordSizeLimit method, of class RecordSizeLimitDelegate. */
    @Test
    public void testGetRecordSizeLimit() {
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "1337";
        assertNull(delegate.getRecordSizeLimit());
        jcommander.parse(args);
        assertEquals(1337, (int) delegate.getRecordSizeLimit());
    }

    @Test
    public void testGetInvalidRecordSizeLimit() {
        args = new String[2];
        args[0] = "-record_size_limit";
        args[1] = "abcdefg";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setRecordSizeLimit method, of class RecordSizeLimitDelegate. */
    @Test
    public void testSetRecordSizeLimit() {
        assertNull(delegate.getRecordSizeLimit());
        delegate.setRecordSizeLimit(1337);
        assertEquals(1337, (int) delegate.getRecordSizeLimit());
    }

    /** Test of applyDelegate method, of class RecordSizeLimitDelegate. */
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
        assertEquals(1337, (int) config.getInboundRecordSizeLimit());
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
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
