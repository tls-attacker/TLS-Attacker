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
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class HeartbeatDelegateTest {

    private HeartbeatDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new HeartbeatDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getHeartbeatMode method, of class HeartbeatDelegate.
     */
    @Test
    public void testGetHeartbeatMode() {
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "PEER_ALLOWED_TO_SEND";
        delegate.setHeartbeatMode(null);
        jcommander.parse(args);
        assertTrue(delegate.getHeartbeatMode() == HeartbeatMode.PEER_ALLOWED_TO_SEND);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidHeartbeatMode() {
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "NOTAVALIDHEARTBEATMODE";
        jcommander.parse(args);
    }

    /**
     * Test of setHeartbeatMode method, of class HeartbeatDelegate.
     */
    @Test
    public void testSetHeartbeatMode() {
        delegate.setHeartbeatMode(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND);
        assertTrue(delegate.getHeartbeatMode() == HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND);
    }

    /**
     * Test of applyDelegate method, of class HeartbeatDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setHeartbeatMode(null);
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "PEER_ALLOWED_TO_SEND";
        jcommander.parse(args);
        assertFalse(config.isAddHeartbeatExtension());
        delegate.applyDelegate(config);
        assertTrue(config.getHeartbeatMode() == HeartbeatMode.PEER_ALLOWED_TO_SEND);
        assertTrue(config.isAddHeartbeatExtension());
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
