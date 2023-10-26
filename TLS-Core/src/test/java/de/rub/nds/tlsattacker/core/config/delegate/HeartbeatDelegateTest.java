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
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class HeartbeatDelegateTest extends AbstractDelegateTest<HeartbeatDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new HeartbeatDelegate());
    }

    /** Test of getHeartbeatMode method, of class HeartbeatDelegate. */
    @Test
    public void testGetHeartbeatMode() {
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "PEER_ALLOWED_TO_SEND";
        delegate.setHeartbeatMode(null);
        jcommander.parse(args);
        assertSame(HeartbeatMode.PEER_ALLOWED_TO_SEND, delegate.getHeartbeatMode());
    }

    @Test
    public void testGetInvalidHeartbeatMode() {
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "NOTAVALIDHEARTBEATMODE";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setHeartbeatMode method, of class HeartbeatDelegate. */
    @Test
    public void testSetHeartbeatMode() {
        delegate.setHeartbeatMode(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND);
        assertSame(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND, delegate.getHeartbeatMode());
    }

    /** Test of applyDelegate method, of class HeartbeatDelegate. */
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
        assertSame(HeartbeatMode.PEER_ALLOWED_TO_SEND, config.getHeartbeatMode());
        assertTrue(config.isAddHeartbeatExtension());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
