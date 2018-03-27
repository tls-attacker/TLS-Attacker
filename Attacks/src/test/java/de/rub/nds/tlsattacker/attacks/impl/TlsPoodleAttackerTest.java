/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import static org.junit.Assert.assertEquals;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerType;
import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;

@Category(DockerTests.class)
public class TlsPoodleAttackerTest {
    private DockerSpotifyTlsServerManager serverManager;
    private TlsServer server = null;

    public TlsPoodleAttackerTest() {
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
        testServer(DockerTlsServerType.OPENSSL, "1.1.0f", false);
    }

    private void testServer(DockerTlsServerType dockerTlsServerType, String version, boolean expectResult) {
        System.out.println("Starting TLS-Poodle tests vs " + dockerTlsServerType.getName() + " " + version
                + " (expected " + new Boolean(expectResult).toString() + ")");
        serverManager = DockerTlsServerManagerFactory.get(dockerTlsServerType, version);
        server = serverManager.getTlsServer();
        TLSPoodleCommandConfig config = new TLSPoodleCommandConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.host + ":" + server.port);
        TLSPoodleAttacker attacker = new TLSPoodleAttacker(config);
        assertEquals(attacker.isVulnerable(), expectResult);
    }

    @Test
    public void testIsVulnerableTrue() {
        testServer(DockerTlsServerType.DAMN_VULNERABLE_OPENSSL, "1.0", true);
    }

}
