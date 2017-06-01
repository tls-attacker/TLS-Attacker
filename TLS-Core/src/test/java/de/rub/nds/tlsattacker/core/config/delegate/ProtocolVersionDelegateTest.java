/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProtocolVersionDelegateTest {

    private ProtocolVersionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public ProtocolVersionDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new ProtocolVersionDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getProtocolVersion method, of class ProtocolVersionDelegate.
     */
    @Test
    public void testGetProtocolVersion() {
        args = new String[2];
        args[0] = "-version";
        args[1] = "TLS12";
        delegate.setProtocolVersion(null);
        assertFalse(delegate.getProtocolVersion() == ProtocolVersion.TLS12);
        jcommander.parse(args);
        assertTrue(delegate.getProtocolVersion() == ProtocolVersion.TLS12);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidProtocolVersion() {
        args = new String[2];
        args[0] = "-version";
        args[1] = "NOTAPROTOCOLVERSION";
        jcommander.parse(args);
    }

    /**
     * Test of setProtocolVersion method, of class ProtocolVersionDelegate.
     */
    @Test
    public void testSetProtocolVersion() {
        delegate.setProtocolVersion(null);
        assertFalse(delegate.getProtocolVersion() == ProtocolVersion.TLS12);
        delegate.setProtocolVersion(ProtocolVersion.TLS12);
        assertTrue(delegate.getProtocolVersion() == ProtocolVersion.TLS12);
    }

    /**
     * Test of applyDelegate method, of class ProtocolVersionDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);
        config.setTransportHandlerType(TransportHandlerType.EAP_TLS);
        args = new String[2];
        args[0] = "-version";
        args[1] = "TLS12";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getHighestProtocolVersion() == ProtocolVersion.TLS12);
        assertTrue(config.getTransportHandlerType() == TransportHandlerType.TCP);
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
