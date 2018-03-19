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
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 * @author robert
 */
@Category(DockerTests.class)
public class BleichenbacherAttackerTest {

    private DockerSpotifyTlsServerManager serverManager;
    private TlsServer server = null;

    public BleichenbacherAttackerTest() {
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
    public void testIsVulnerableFalse() {
        System.out.println("Starting BleichenbacherAttack tests vs Openssl 1.1.0f (expected false)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.OPENSSL, "1.1.0f");
        server = serverManager.getTlsServer();
        BleichenbacherCommandConfig config = new BleichenbacherCommandConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(config);
        assertFalse(attacker.isVulnerable());
    }

    @Test
    public void testIsVulnerableTrue() {
        System.out.println("Starting BleichenbacherAttack tests vs Openssl 0.9.8 (expected true)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.OPENSSL, "0.9.6");
        server = serverManager.getTlsServer();
        BleichenbacherCommandConfig config = new BleichenbacherCommandConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(config);
        assertTrue(attacker.isVulnerable());
    }

    @Test
    public void testExecuteAttack() {

    }

}
