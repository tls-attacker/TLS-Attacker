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
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TransportHandlerDelegateTest extends AbstractDelegateTest<TransportHandlerDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new TransportHandlerDelegate());
    }

    /** Test of getTransportHandlerType method, of class TransportHandlerDelegate. */
    @Test
    public void testGetTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "UDP";
        assertNotSame(TransportHandlerType.UDP, delegate.getTransportHandlerType());
        jcommander.parse(args);
        assertSame(TransportHandlerType.UDP, delegate.getTransportHandlerType());
    }

    @Test
    public void testGetInvalidTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "NOTATRANSPORTHANDLER";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setTransportHandlerType method, of class TransportHandlerDelegate. */
    @Test
    public void testSetTransportHandlerType() {
        assertNotSame(TransportHandlerType.UDP, delegate.getTransportHandlerType());
        delegate.setTransportHandlerType(TransportHandlerType.UDP);
        assertSame(TransportHandlerType.UDP, delegate.getTransportHandlerType());
    }

    /** Test of applyDelegate method, of class TransportHandlerDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP);
        config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.TCP);
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "UDP";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(
                TransportHandlerType.UDP,
                config.getDefaultClientConnection().getTransportHandlerType());
        assertSame(
                TransportHandlerType.UDP,
                config.getDefaultServerConnection().getTransportHandlerType());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(
                EqualsBuilder.reflectionEquals(
                        config, config2, "keyStore", "ourCertificate", "echConfig")); // little
        // ugly
    }
}
