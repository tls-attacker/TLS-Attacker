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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class MitmDelegateTest extends AbstractDelegateTest<MitmDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new MitmDelegate());
    }

    @Test
    public void testParseValidParameters() {
        String expectedServerConStr = "1234";
        String expectedClientConStr = "localhost:1234";
        args = new String[4];
        args[0] = "-accept";
        args[1] = expectedServerConStr;
        args[2] = "-connect";
        args[3] = expectedClientConStr;

        assertNull(delegate.getInboundConnectionStr());
        assertNull(delegate.getOutboundConnectionStr());
        jcommander.parse(args);

        String actualInConStr = delegate.getInboundConnectionStr();
        assertNotNull(actualInConStr);
        assertEquals(expectedServerConStr, actualInConStr);

        String actualOutConStr = delegate.getOutboundConnectionStr();
        assertNotNull(actualOutConStr);
        assertEquals(expectedClientConStr, actualOutConStr);
    }

    @Test
    public void testParseValidParametersWithAlias() {
        String expectedServerConStr = "someAlias:1234";
        String expectedClientConStr = "anotherAlias:localhost:1234";
        args = new String[4];
        args[0] = "-accept";
        args[1] = expectedServerConStr;
        args[2] = "-connect";
        args[3] = expectedClientConStr;

        assertNull(delegate.getInboundConnectionStr());
        assertNull(delegate.getOutboundConnectionStr());
        jcommander.parse(args);

        String actualInConStr = delegate.getInboundConnectionStr();
        assertNotNull(actualInConStr);
        assertEquals(expectedServerConStr, actualInConStr);

        String actualOutConStr = delegate.getOutboundConnectionStr();
        assertNotNull(actualOutConStr);
        assertEquals(expectedClientConStr, actualOutConStr);
    }

    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setDefaultClientConnection(null);
        config.setDefaultServerConnection(null);
        InboundConnection expectedServerCon = new InboundConnection("accept:1234", 1234);
        OutboundConnection expectedClientCon =
                new OutboundConnection("remotehost:4321", 4321, "remotehost");
        args = new String[4];
        args[0] = "-accept";
        args[1] = "1234";
        args[2] = "-connect";
        args[3] = "remotehost:4321";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        InboundConnection actualServerCon = config.getDefaultServerConnection();
        OutboundConnection actualClientCon = config.getDefaultClientConnection();
        assertEquals(expectedServerCon, actualServerCon);
        assertEquals(expectedClientCon, actualClientCon);
    }

    /** Make sure that applying with port = null fails properly. */
    @Test
    public void testApplyDelegateInvalidPorts() {
        Config config = Config.createConfig();
        String validPort = "aliasOrHost:8420";
        List<String> invalidPorts = new ArrayList<>();
        invalidPorts.add("badPort:0");
        invalidPorts.add("badPort:-1");
        invalidPorts.add("badPort:65536");
        for (String badPort : invalidPorts) {
            delegate.setInboundConnectionStr(badPort);
            delegate.setOutboundConnectionStr(validPort);
            ParameterException exception =
                    assertThrows(ParameterException.class, () -> delegate.applyDelegate(config));
            assertTrue(
                    exception
                            .getMessage()
                            .startsWith("port must be in interval [1,65535], but is"));

            delegate.setInboundConnectionStr(validPort);
            delegate.setOutboundConnectionStr(badPort);
            exception =
                    assertThrows(ParameterException.class, () -> delegate.applyDelegate(config));
            assertTrue(
                    exception
                            .getMessage()
                            .startsWith("port must be in interval [1,65535], but is"));
        }
    }

    @Test
    public void testApplyDelegateWithEmptyConfig() {
        Config config = Config.createConfig();
        config.setDefaultServerConnection(null);
        config.setDefaultClientConnection(null);
        String expectedHostOrAlias = "aliasOrHost";
        String expectedPort = "8420";
        String param = expectedHostOrAlias + ':' + expectedPort;

        delegate.setInboundConnectionStr(param);
        delegate.setOutboundConnectionStr(param);
        delegate.applyDelegate(config);

        AliasedConnection actualServerCon = config.getDefaultServerConnection();
        AliasedConnection actualClientCon = config.getDefaultClientConnection();
        assertNotNull(actualServerCon);
        assertNotNull(actualClientCon);

        assertEquals(expectedHostOrAlias, actualServerCon.getAlias());
        assertEquals(Integer.parseInt(expectedPort), actualServerCon.getPort().intValue());
        assertNull(actualServerCon.getHostname());
        assertEquals(param, actualClientCon.getAlias());
        assertEquals(Integer.parseInt(expectedPort), actualClientCon.getPort().intValue());
        assertEquals(expectedHostOrAlias, actualClientCon.getHostname());
    }

    @Test
    @Disabled("Not implemented")
    public void testApplyDelegateWithMissingConnection() {}
}
