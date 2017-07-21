/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsConfigTest {

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testReadFromResource() {
        assertNotNull(Config.createConfig());
    }

    @Test
    public void testDefaultCertificates() throws IOException {
        Config config = Config.createConfig();
        Certificate cert = Certificate.parse(new ByteArrayInputStream(config.getDefaultRsaCertificate()));
        cert = Certificate.parse(new ByteArrayInputStream(config.getDefaultEcCertificate()));
        cert = Certificate.parse(new ByteArrayInputStream(config.getDefaultDsaCertificate()));
    }
}
