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
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TransportHandlerDelegateTest {

    private TransportHandlerDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new TransportHandlerDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getTransportHandlerType method, of class
     * TransportHandlerDelegate.
     */
    @Test
    public void testGetTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "UDP";
        assertFalse(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
        jcommander.parse(args);
        assertTrue(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidTransportHandlerType() {
        args = new String[2];
        args[0] = "-transport_handler_type";
        args[1] = "NOTATRANSPORTHANDLER";
        jcommander.parse(args);
    }

    /**
     * Test of setTransportHandlerType method, of class
     * TransportHandlerDelegate.
     */
    @Test
    public void testSetTransportHandlerType() {
        assertFalse(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
        delegate.setTransportHandlerType(TransportHandlerType.UDP);
        assertTrue(delegate.getTransportHandlerType() == TransportHandlerType.UDP);
    }

    /**
     * Test of applyDelegate method, of class TransportHandlerDelegate.
     */
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

        assertThat(config.getDefaultClientConnection().getTransportHandlerType(), equalTo(TransportHandlerType.UDP));
        assertThat(config.getDefaultServerConnection().getTransportHandlerType(), equalTo(TransportHandlerType.UDP));
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
