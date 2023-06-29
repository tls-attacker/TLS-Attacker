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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ProtocolVersionDelegateTest extends AbstractDelegateTest<ProtocolVersionDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new ProtocolVersionDelegate());
    }

    /** Test of getProtocolVersion method, of class ProtocolVersionDelegate. */
    @Test
    public void testGetProtocolVersion() {
        String[] args = new String[2];
        args[0] = "-version";
        args[1] = "TLS12";
        delegate.setProtocolVersion(null);
        assertNotSame(ProtocolVersion.TLS12, delegate.getProtocolVersion());
        jcommander.parse(args);
        assertSame(ProtocolVersion.TLS12, delegate.getProtocolVersion());
    }

    @Test
    public void testGetInvalidProtocolVersion() {
        String[] args = new String[2];
        args[0] = "-version";
        args[1] = "NOTAPROTOCOLVERSION";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setProtocolVersion method, of class ProtocolVersionDelegate. */
    @Test
    public void testSetProtocolVersion() {
        delegate.setProtocolVersion(null);
        assertNotSame(ProtocolVersion.TLS12, delegate.getProtocolVersion());
        delegate.setProtocolVersion(ProtocolVersion.TLS12);
        assertSame(ProtocolVersion.TLS12, delegate.getProtocolVersion());
    }

    /** Test of applyDelegate method, of class ProtocolVersionDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);
        config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.EAP_TLS);
        config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.EAP_TLS);
        String[] args = new String[2];
        args[0] = "-version";
        args[1] = "TLS12";
        assertSame(ProtocolVersion.SSL2, config.getHighestProtocolVersion());
        assertSame(
                TransportHandlerType.EAP_TLS,
                config.getDefaultClientConnection().getTransportHandlerType());
        assertSame(
                TransportHandlerType.EAP_TLS,
                config.getDefaultServerConnection().getTransportHandlerType());

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertSame(ProtocolVersion.TLS12, config.getHighestProtocolVersion());
        assertSame(
                TransportHandlerType.TCP,
                config.getDefaultClientConnection().getTransportHandlerType());
        assertSame(
                TransportHandlerType.TCP,
                config.getDefaultServerConnection().getTransportHandlerType());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
