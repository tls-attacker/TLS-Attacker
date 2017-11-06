/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;


public class SignatureCalculatorTest {

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of generateRSASignature method, of class SignatureCalculator.
     */
    @Test
    public void testGenerateRSASignature() {
        SignatureAndHashAlgorithm sigAndHash = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1);
        TlsContext ctx = new TlsContext();
        Chooser chooser = ctx.getChooser();

        byte[] signature = SignatureCalculator.generateSignature(sigAndHash, chooser, new byte[] { 0, 12, 3 });
        System.out.println(ArrayConverter.bytesToHexString(signature));
    }

    /**
     * Test of generateDSASignature method, of class SignatureCalculator.
     */
    @Test
    public void testGenerateDSASignature() {
    }

    /**
     * Test of generateECDSASignature method, of class SignatureCalculator.
     */
    @Test
    public void testGenerateECDSASignature() {
    }

    /**
     * Test of generateAnonymousSignature method, of class SignatureCalculator.
     */
    @Test
    public void testGenerateAnonymousSignature() {
    }

}
