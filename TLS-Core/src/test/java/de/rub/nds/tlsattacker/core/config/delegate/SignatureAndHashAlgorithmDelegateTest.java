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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SignatureAndHashAlgorithmDelegateTest {

    private SignatureAndHashAlgorithmDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new SignatureAndHashAlgorithmDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getSignatureAndHashAlgorithms method, of class
     * SignatureAndHashAlgorithmDelegate.
     */
    @Test
    public void testGetSignatureAndHashAlgorithms() {
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_SHA512,DSA_SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(SignatureAndHashAlgorithm.RSA_SHA512));
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(SignatureAndHashAlgorithm.DSA_SHA512));
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidSignatureHashAlgorithms() {
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_STSDHA512,DsdfsdSA_SHA512";
        jcommander.parse(args);
    }

    /**
     * Test of setSignatureAndHashAlgorithms method, of class
     * SignatureAndHashAlgorithmDelegate.
     */
    @Test
    public void testSetSignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgoList = new LinkedList<>();
        signatureAndHashAlgoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        delegate.setSignatureAndHashAlgorithms(signatureAndHashAlgoList);
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(SignatureAndHashAlgorithm.ANONYMOUS_SHA1));
    }

    /**
     * Test of applyDelegate method, of class SignatureAndHashAlgorithmDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_SHA512,DSA_SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        assertFalse(config.isAddSignatureAndHashAlgrorithmsExtension());
        delegate.applyDelegate(config);
        assertTrue(config.isAddSignatureAndHashAlgrorithmsExtension());
        assertTrue(config.getDefaultClientSupportedSignatureAndHashAlgorithms().contains(
                SignatureAndHashAlgorithm.RSA_SHA512));
        assertTrue(config.getDefaultClientSupportedSignatureAndHashAlgorithms().contains(
                SignatureAndHashAlgorithm.DSA_SHA512));
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }

}
