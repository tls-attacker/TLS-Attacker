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

public class SessionResumptionDelegateTest extends AbstractDelegateTest<SessionResumptionDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new SessionResumptionDelegate());
    }

    /** Test of getSessionId method, of class SessionResumptionDelegate. */
    @Test
    public void testGetSessionID() {
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        delegate.setSessionId(null);
        jcommander.parse(args);
        byte[] expected = {
            (byte) 0x00,
            (byte) 0x11,
            (byte) 0x22,
            (byte) 0x33,
            (byte) 0x44,
            (byte) 0x55,
            (byte) 0x66,
            (byte) 0x77,
            (byte) 0x88,
            (byte) 0x99,
            (byte) 0xAA,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0xDD,
            (byte) 0xEE,
            (byte) 0xFF
        };
        assertArrayEquals(delegate.getSessionId(), expected);
    }

    @Test
    public void testGetInvalidSessionId() {
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "NOTAHEXSTRING";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setSessionID method, of class SessionResumptionDelegate. */
    @Test
    public void testSetSessionID() {
        byte[] expected = {
            (byte) 0x00,
            (byte) 0x11,
            (byte) 0x22,
            (byte) 0x33,
            (byte) 0x44,
            (byte) 0x55,
            (byte) 0x66,
            (byte) 0x77,
            (byte) 0x88,
            (byte) 0x99,
            (byte) 0xAA,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0xDD,
            (byte) 0xEE,
            (byte) 0xFF
        };
        delegate.setSessionId(expected);
        assertArrayEquals(delegate.getSessionId(), expected);
    }

    /** Test of applyDelegate method, of class SessionResumptionDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        delegate.setSessionId(null);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        byte[] expected = {
            (byte) 0x00,
            (byte) 0x11,
            (byte) 0x22,
            (byte) 0x33,
            (byte) 0x44,
            (byte) 0x55,
            (byte) 0x66,
            (byte) 0x77,
            (byte) 0x88,
            (byte) 0x99,
            (byte) 0xAA,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0xDD,
            (byte) 0xEE,
            (byte) 0xFF
        };
        assertArrayEquals(config.getDefaultClientSessionId(), expected);
        assertArrayEquals(config.getDefaultServerSessionId(), expected);
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
