/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 *
 */
public class Pkcs1VectorGeneratorTest {

    /**
     * Test of generatePlainPkcs1Vectors method, of class Pkcs1VectorGenerator.
     */
    @Test
    public void testGeneratePlainPkcs1Vectors() {
        List<Pkcs1Vector> vectors = Pkcs1VectorGenerator.generatePlainPkcs1Vectors(2048,
                BleichenbacherCommandConfig.Type.FAST, ProtocolVersion.TLS12);
        Assert.assertNotNull(vectors);
        Assert.assertEquals("11 PKCS#1 vectors should be generated", 12, vectors.size());
    }

}
