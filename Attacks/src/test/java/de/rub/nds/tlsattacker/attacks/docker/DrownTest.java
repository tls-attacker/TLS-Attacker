/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.docker;

import de.rub.nds.tls.subject.TlsImplementationType;
import static org.junit.Assert.assertEquals;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tlsattacker.attacks.config.DrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsattacker.attacks.impl.DrownAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;

@Category(DockerTests.class)
public class DrownTest {

    private static final String PARAMETERS_NO_CIPHERSUITES = "-no_ssl3 -cipher AES";
    private static final String PARAMETERS_DES_IN_CIPHERSUITES = "-ssl2 -cipher DES";
    private static final String PARAMETERS_DES3_IN_CIPHERSUITES = "-ssl2 -cipher 3DES";
    private static final String PARAMETERS_NO_SSL2 = "-no_ssl2";

    private static final String VERSION_WITHOUT_CIPHERSUITE_SELECTION_BUG = "1.0.2f";
    private static final String VERSION_WITH_CIPHERSUITE_SELECTION_BUG = "1.0.2e";

    private static TlsServer server;
    private static DockerSpotifyTlsServerManager serverManager;

    private static void getOpenSSLServer(String version, String parameters) {
        try {
            System.out.println("Trying to initialize DrownTest");
            UnlimitedStrengthEnabler.enable();
            Security.addProvider(new BouncyCastleProvider());
            DockerTlsServerManagerFactory factory = new DockerTlsServerManagerFactory();
            server = factory.get(TlsImplementationType.OPENSSL, version, parameters);
            System.out.println("Started the Docker server at:" + server.getHost() + ":" + server.getPort());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testServerWithoutCiphersuitesDoesntAcceptRC4() {
        testOpenSSLVersion(VERSION_WITHOUT_CIPHERSUITE_SELECTION_BUG, false, PARAMETERS_NO_CIPHERSUITES);
    }

    @Test
    public void testServerWithoutCiphersuitesAcceptsRC4() {
        testOpenSSLVersion(VERSION_WITH_CIPHERSUITE_SELECTION_BUG, true, PARAMETERS_NO_CIPHERSUITES);
    }

    @Test
    public void testServerWithDesInCiphersuites() {
        testOpenSSLVersion(VERSION_WITHOUT_CIPHERSUITE_SELECTION_BUG, true, PARAMETERS_DES_IN_CIPHERSUITES);
    }

    @Test
    public void testServerWithDes3InCiphersuitesDoesntAcceptRC4() {
        testOpenSSLVersion(VERSION_WITHOUT_CIPHERSUITE_SELECTION_BUG, false, PARAMETERS_DES3_IN_CIPHERSUITES);
    }

    @Test
    public void testTLSServer() {
        testOpenSSLVersion(VERSION_WITHOUT_CIPHERSUITE_SELECTION_BUG, false, PARAMETERS_NO_SSL2);
    }

    private void testOpenSSLVersion(String version, Boolean shouldBeVulnerable, String parameters) {
        getOpenSSLServer(version, parameters);
        DrownCommandConfig config = new DrownCommandConfig(new GeneralAttackDelegate());
        ClientDelegate delegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        delegate.setHost(server.getHost() + ":" + server.getPort());

        DrownAttacker attacker = new DrownAttacker(config);
        try {
            Boolean result = attacker.checkVulnerability();
            // System.out.println(serverManager.getLogsFromTlsServer(server));
            assertEquals(result, shouldBeVulnerable);
            System.out.println("Vulnerable:" + (result == null ? "Uncertain" : result.toString()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        server.kill();
    }

}
