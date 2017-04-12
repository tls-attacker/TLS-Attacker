/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.unittest;

import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfigIO;
import java.io.File;
import java.io.IOException;
import static org.junit.Assert.assertNotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsConfigIOTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void test() throws IOException {
        File f = folder.newFile();
        TlsConfig config = TlsConfig.createConfig();
        TlsConfigIO.write(config, f);
        config = TlsConfigIO.read(f);
        assertNotNull(config);
    }
}
