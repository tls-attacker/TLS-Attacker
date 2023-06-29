/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ClientAuthenticationDelegateTest
        extends AbstractDelegateTest<ClientAuthenticationDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new ClientAuthenticationDelegate());
    }

    /** Test of isClientAuthentication method, of class ClientAuthenticationDelegate. */
    @Test
    public void testIsClientAuthentication() {
        args = new String[1];
        args[0] = "-client_authentication";
        assertNull(delegate.isClientAuthentication());
        jcommander.parse(args);
        assertTrue(delegate.isClientAuthentication());
    }

    /** Test of setClientAuthentication method, of class ClientAuthenticationDelegate. */
    @Test
    public void testSetClientAuthentication() {
        assertNull(delegate.isClientAuthentication());
        delegate.setClientAuthentication(true);
        assertTrue(delegate.isClientAuthentication());
    }

    /** Test of applyDelegate method, of class ClientAuthenticationDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setClientAuthentication(false);
        args = new String[1];
        args[0] = "-client_authentication";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isClientAuthentication());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
