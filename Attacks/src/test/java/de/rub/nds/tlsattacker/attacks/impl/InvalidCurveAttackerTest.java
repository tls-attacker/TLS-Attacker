/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
    @Ignore
    public void testIsVulnerableFalse() {
        System.out.println("Starting InvalidCurveAttacker tests vs BouncyCastle 1.52 (expected false)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.BOUNCYCASTLE, "1.54");
        server = serverManager.getTlsServer();
        InvalidCurveAttackConfig config = new InvalidCurveAttackConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(config, config.createConfig());
        assertTrue(attacker.isVulnerable() == Boolean.FALSE);
    }

    @Test
    @Ignore
    public void testIsVulnerableTrue() {
        System.out.println("Starting InvalidCurveAttacker tests vs BouncyCastle 1.50 (expected true)");
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.BOUNCYCASTLE, "1.50");
        server = serverManager.getTlsServer();
        InvalidCurveAttackConfig config = new InvalidCurveAttackConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(config, config.createConfig());
        assertTrue(attacker.isVulnerable() == Boolean.TRUE);
    }

    @Test
    public void testExecuteAttack() {

    }
}
