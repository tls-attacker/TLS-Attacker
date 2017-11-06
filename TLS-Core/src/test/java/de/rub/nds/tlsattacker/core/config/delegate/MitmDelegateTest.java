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
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.util.ArrayList;
import java.util.List;
import static org.hamcrest.CoreMatchers.startsWith;
import org.hamcrest.Matcher;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class MitmDelegateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private MitmDelegate delegate;
    private JCommander jcommander;
    private String[] args;
    List<String> expectedAccepting = new ArrayList<>();
    List<String> expectedConnecting = new ArrayList<>();
    List<ConnectionEnd> expected = new ArrayList<>();
    Config config;
    ServerConnectionEnd dummyConEnd = new ServerConnectionEnd();

    @Before
    public void setUp() {
        this.delegate = new MitmDelegate();
        this.jcommander = new JCommander(delegate);
        this.config = Config.createConfig();
    }

    @Test
    public void testGetSingleConnectionEnds() {
        expectedAccepting.clear();
        expectedConnecting.clear();
        expectedAccepting.add("1234");
        expectedConnecting.add("localhost:1234");
        args = new String[4];
        args[0] = "-accept";
        args[1] = expectedAccepting.get(0);
        args[2] = "-connect";
        args[3] = expectedConnecting.get(0);

        assertTrue(delegate.getAcceptingConnectionEnds().isEmpty());
        assertTrue(delegate.getConnectingConnectionEnds().isEmpty());
        jcommander.parse(args);
        List<String> accConEndStrs = delegate.getAcceptingConnectionEnds();
        assertNotNull(accConEndStrs);
        assertEquals(accConEndStrs.size(), 1);
        assertEquals(accConEndStrs, expectedAccepting);

        List<String> conConEndStrs = delegate.getConnectingConnectionEnds();
        assertNotNull(conConEndStrs);
        assertEquals(conConEndStrs.size(), 1);
        assertEquals(conConEndStrs, expectedConnecting);
    }

    @Test
    public void testGetSingleConnectionEndsWithAlias() {
        expectedAccepting.clear();
        expectedConnecting.clear();
        expectedAccepting.add("someAlias:1234");
        expectedConnecting.add("anotherAlias:localhost:1234");
        args = new String[4];
        args[0] = "-accept";
        args[1] = expectedAccepting.get(0);
        args[2] = "-connect";
        args[3] = expectedConnecting.get(0);

        assertTrue(delegate.getAcceptingConnectionEnds().isEmpty());
        assertTrue(delegate.getConnectingConnectionEnds().isEmpty());
        jcommander.parse(args);
        List<String> accConEndStrs = delegate.getAcceptingConnectionEnds();
        assertNotNull(accConEndStrs);
        assertEquals(accConEndStrs.size(), 1);
        assertEquals(accConEndStrs, expectedAccepting);

        List<String> conConEndStrs = delegate.getConnectingConnectionEnds();
        assertNotNull(conConEndStrs);
        assertEquals(conConEndStrs.size(), 1);
        assertEquals(conConEndStrs, expectedConnecting);
    }

    @Test
    public void testGetMultipleConnectionEndsWithAlias() {
        expectedAccepting.clear();
        expectedConnecting.clear();
        expectedAccepting.add("alias1:1");
        expectedAccepting.add("alias2:22");
        expectedAccepting.add("alias3:333");
        expectedConnecting.add("anotherAlias1:localhost:1");
        expectedConnecting.add("anotherAlias2:remotehost:12");
        expectedConnecting.add("anotherAlias3:nullhost:123");

        args = new String[(expectedAccepting.size() + expectedConnecting.size()) * 2];
        int i = 0;
        for (int j = 0; j < expectedAccepting.size(); j++) {
            args[i] = "-accept";
            args[i + 1] = expectedAccepting.get(j);
            i += 2;
        }

        for (int j = 0; j < expectedConnecting.size(); j++) {
            args[i] = "-connect";
            args[i + 1] = expectedConnecting.get(j);
            i += 2;
        }

        assertTrue(delegate.getAcceptingConnectionEnds().isEmpty());
        assertTrue(delegate.getConnectingConnectionEnds().isEmpty());
        jcommander.parse(args);
        List<String> accConEndStrs = delegate.getAcceptingConnectionEnds();
        assertNotNull(accConEndStrs);
        assertEquals(accConEndStrs.size(), 3);
        assertEquals(accConEndStrs, expectedAccepting);

        List<String> conConEndStrs = delegate.getConnectingConnectionEnds();
        assertNotNull(conConEndStrs);
        assertEquals(conConEndStrs.size(), 3);
        assertEquals(conConEndStrs, expectedConnecting);
    }

    @Test
    public void testApplyDelegateSingleConnectionEnds() {
        config.clearConnectionEnds();
        config.addConnectionEnd(dummyConEnd);

        expected.clear();
        expected.add(new ServerConnectionEnd("accept:1234", 1234));
        expected.add(new ClientConnectionEnd("remotehost:4321", 4321, "remotehost"));
        args = new String[4];
        args[0] = "-accept";
        args[1] = "1234";
        args[2] = "-connect";
        args[3] = "remotehost:4321";

        assertEquals(config.getConnectionEnds().size(), 1);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        List<ConnectionEnd> actual = config.getConnectionEnds();
        assertNotNull(actual);
        assertEquals(actual.size(), 2);
        assertEquals(expected, actual);
    }

    @Test
    public void testApplyDelegateMultipleConnectionEnds() {
        config.clearConnectionEnds();
        config.addConnectionEnd(dummyConEnd);

        expected.clear();
        expected.add(new ServerConnectionEnd("accept:1234", 1234));
        expected.add(new ClientConnectionEnd("remotehost:4321", 4321, "remotehost"));
        args = new String[4];
        args[0] = "-accept";
        args[1] = "1234";
        args[2] = "-connect";
        args[3] = "remotehost:4321";

        jcommander.parse(args);
        delegate.applyDelegate(config);
        List<ConnectionEnd> actual = config.getConnectionEnds();
        assertNotNull(actual);
        assertEquals(actual.size(), 2);
        assertEquals(expected, actual);
    }

    /**
     * Make sure that applying with port = null fails properly.
     */
    @Test
    public void testApplyDelegateInvalidPorts() {
        Matcher expectedExMsg = startsWith("port must be in interval [0,65535], but is");
        List<String> validPorts = new ArrayList<>();
        validPorts.add("aliasOrHost:8420");
        List<String> invalidPorts = new ArrayList<>();
        invalidPorts.add("aliasOrHost:0");
        delegate.setAcceptingConnectionEnds(invalidPorts);
        delegate.setConnectingConnectionEnds(validPorts);
        exception.expect(ParameterException.class);
        exception.expectMessage(expectedExMsg);
        delegate.applyDelegate(config);

        delegate.setAcceptingConnectionEnds(validPorts);
        delegate.setConnectingConnectionEnds(invalidPorts);
        exception.expect(ParameterException.class);
        exception.expectMessage(expectedExMsg);
        delegate.applyDelegate(config);

        invalidPorts.set(0, "hostOrAlias:65536");
        delegate.setAcceptingConnectionEnds(validPorts);
        delegate.setConnectingConnectionEnds(invalidPorts);
        exception.expect(ParameterException.class);
        exception.expectMessage(expectedExMsg);
        delegate.applyDelegate(config);

        delegate.setAcceptingConnectionEnds(validPorts);
        delegate.setConnectingConnectionEnds(invalidPorts);
        exception.expect(ParameterException.class);
        exception.expectMessage(expectedExMsg);
        delegate.applyDelegate(config);
    }

    /**
     * Make sure that applying this delegate removes all previously known
     * connection ends.
     */
    @Test
    public void testApplyDelegateClearsOldConnectionEnds() {
        config.clearConnectionEnds();
        config.addConnectionEnd(dummyConEnd);
        expected.clear();
        expected.add(new ClientConnectionEnd("alias1", 1111, "hostname1"));
        List<String> s = new ArrayList<>();
        s.add("alias1:hostname1:1111");

        delegate.setConnectingConnectionEnds(s);
        delegate.applyDelegate(config);
        assertTrue(config.getConnectionEnds().size() == 1);
        // Intentionally try single context access. Should pass without
        // problems.
        ConnectionEnd actual = config.getConnectionEnd();
        assertEquals(expected.get(0), actual);
    }

}
