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
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RenegotiationDelegateTest {

    private RenegotiationDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new RenegotiationDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isLegacyRenegotiation method, of class RenegotiationDelegate.
     */
    @Test
    public void testIsLegacyRenegotiation() {
        args = new String[1];
        args[0] = "-legacy_renegotiation";
        assertTrue(delegate.isLegacyRenegotiation() == null);
        jcommander.parse(args);
        assertTrue(delegate.isLegacyRenegotiation());
    }

    /**
     * Test of setLegacyRenegotiation method, of class RenegotiationDelegate.
     */
    @Test
    public void testSetLegacyRenegotiation() {
        assertTrue(delegate.isLegacyRenegotiation() == null);
        delegate.setLegacyRenegotiation(true);
        assertTrue(delegate.isLegacyRenegotiation());
    }

    /**
     * Test of applyDelegate method, of class RenegotiationDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setRenegotiation(false);
        args = new String[1];
        args[0] = "-legacy_renegotiation";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isRenegotiation());
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
