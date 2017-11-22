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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import java.util.ArrayList;
import java.util.List;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.startsWith;
import org.hamcrest.Matcher;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class MitmDelegateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private MitmDelegate delegate;
    private JCommander jcommander;
    private String[] args;
    String expectedClientConStr;
    String expectedServerConStr;
    Config config;
    InboundConnection dummyServerCon;
    OutboundConnection dummyClientCon;
    InboundConnection expectedServerCon;
    OutboundConnection expectedClientCon;

    @Before
    public void setUp() {
        this.delegate = new MitmDelegate();
        this.jcommander = new JCommander(delegate);
        this.config = Config.createConfig();
    }

    @Test
    public void testParseValidParameters() {
        expectedServerConStr = "1234";
        expectedClientConStr = "localhost:1234";
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
        assertThat(actualInConStr, equalTo(expectedServerConStr));

        String actualOutConStr = delegate.getOutboundConnectionStr();
        assertNotNull(actualOutConStr);
        assertThat(actualOutConStr, equalTo(expectedClientConStr));
    }

    @Test
    public void testParseValidParametersWithAlias() {
        expectedServerConStr = "someAlias:1234";
        expectedClientConStr = "anotherAlias:localhost:1234";
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
        assertThat(actualInConStr, equalTo(expectedServerConStr));

        String actualOutConStr = delegate.getOutboundConnectionStr();
        assertNotNull(actualOutConStr);
        assertThat(actualOutConStr, equalTo(expectedClientConStr));
    }

    @Test
    public void testApplyDelegate() {
        config.setDefaultClientConnection(dummyClientCon);
        config.setDefaultServerConnection(dummyServerCon);
        expectedServerCon = new InboundConnection("accept:1234", 1234);
        expectedClientCon = new OutboundConnection("remotehost:4321", 4321, "remotehost");
        args = new String[4];
        args[0] = "-accept";
        args[1] = "1234";
        args[2] = "-connect";
        args[3] = "remotehost:4321";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        InboundConnection actualServerCon = config.getDefaultServerConnection();
        OutboundConnection actualClientCon = config.getDefaultClientConnection();
        assertThat(actualServerCon, equalTo(expectedServerCon));
        assertThat(actualClientCon, equalTo(expectedClientCon));
    }

    /**
     * Make sure that applying with port = null fails properly.
     */
    @Test
    public void testApplyDelegateInvalidPorts() {
        Matcher expectedExMsg = startsWith("port must be in interval [0,65535], but is");
        String validPort = "aliasOrHost:8420";
        List<String> invalidPorts = new ArrayList<>();
        invalidPorts.add("badPort:0");
        invalidPorts.add("badPort:-1");
        invalidPorts.add("badPort:65536");
        for (String badPort : invalidPorts) {
            delegate.setInboundConnectionStr(badPort);
            delegate.setOutboundConnectionStr(validPort);
            exception.expect(ParameterException.class);
            exception.expectMessage(expectedExMsg);
            delegate.applyDelegate(config);

            delegate.setInboundConnectionStr(validPort);
            delegate.setOutboundConnectionStr(badPort);
            exception.expect(ParameterException.class);
            exception.expectMessage(expectedExMsg);
            delegate.applyDelegate(config);
        }
    }

    @Test
    public void testApplyDelegateWithEmptyConfig() {
        Config config = Config.createConfig();
        config.setDefaultServerConnection(null);
        config.setDefaultClientConnection(null);
        String expectedHostOrAlias = "aliasOrHost";
        String expectedPort = "8420";
        StringBuilder sb = new StringBuilder();
        String param = sb.append(expectedHostOrAlias).append(':').append(expectedPort).toString();

        delegate.setInboundConnectionStr(param);
        delegate.setOutboundConnectionStr(param);
        delegate.applyDelegate(config);

        AliasedConnection actualServerCon = config.getDefaultServerConnection();
        AliasedConnection actualClientCon = config.getDefaultClientConnection();
        assertNotNull(actualServerCon);
        assertNotNull(actualClientCon);

        assertThat(actualServerCon.getAlias(), equalTo(expectedHostOrAlias));
        assertThat(actualServerCon.getPort(), equalTo(Integer.parseInt(expectedPort)));
        assertThat(actualServerCon.getHostname(), equalTo(null));
        assertThat(actualClientCon.getAlias(), equalTo(param));
        assertThat(actualClientCon.getPort(), equalTo(Integer.parseInt(expectedPort)));
        assertThat(actualClientCon.getHostname(), equalTo(expectedHostOrAlias));
    }

    @Test
    @Ignore("Implement me!")
    public void testApplyDelegateWithMissingConnection() {

    }
}
