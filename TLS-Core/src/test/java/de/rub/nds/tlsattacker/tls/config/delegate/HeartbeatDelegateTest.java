/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatDelegateTest {

    private HeartbeatDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public HeartbeatDelegateTest() {
    }

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
        TlsConfig config = TlsConfig.createConfig();
        config.setHeartbeatMode(null);
        args = new String[2];
        args[0] = "-heartbeat_mode";
        args[1] = "PEER_ALLOWED_TO_SEND";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getHeartbeatMode() == HeartbeatMode.PEER_ALLOWED_TO_SEND);
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
