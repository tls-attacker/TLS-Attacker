/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerType;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(DockerTests.class)
public class InvalidCurveAttackerTest {

    private DockerSpotifyTlsServerManager serverManager;
    private TlsServer server = null;

    public InvalidCurveAttackerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
        UnlimitedStrengthEnabler.enable();
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
        if (server != null) {
            server.kill();
        }
    }

    @Test
    public void testIsVulnerableFalse() throws Exception {
        System.out.println("Starting InvalidCurveAttacker tests vs BouncyCastle 1.58 (expected false)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.JSSE, "openjdk:7u151-jre-slim-bc-1-50");
        server = serverManager.getTlsServer();
        InvalidCurveAttackConfig config = new InvalidCurveAttackConfig(new GeneralAttackDelegate());
        config.setEphemeral(true);
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        while (!isOnline(server.host, server.port))
            ;
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(config);
        assertTrue(attacker.isVulnerable() == Boolean.FALSE);
        server.kill();
    }

    @Test
    public void testIsVulnerableTrue() throws Exception {
        System.out.println("Starting InvalidCurveAttacker tests vs JSSE with BouncyCastle 1.50 (expected true)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.JSSE_WITH_BC, "openjdk:7u151-jre-slim-bc-1-50");
        server = serverManager.getTlsServer();
        InvalidCurveAttackConfig config = new InvalidCurveAttackConfig(new GeneralAttackDelegate());
        config.setEphemeral(true);
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        while (!isOnline(server.host, server.port))
            ;
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(config);
        assertTrue(attacker.isVulnerable() == Boolean.TRUE);
        server.kill();
    }

    @Test
    public void testExecuteAttack() {

    }

    public static boolean isOnline(String address, int port) {
        boolean b = true;
        System.out.println("waiting");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ex) {
            Logger.getLogger(InvalidCurveAttackerTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            InetSocketAddress sa = new InetSocketAddress(address, port);
            Socket ss = new Socket();
            ss.connect(sa);
            ss.close();
        } catch (IOException e) {
            b = false;
            System.out.println(e.toString());
        }
        return b;
    }
}
