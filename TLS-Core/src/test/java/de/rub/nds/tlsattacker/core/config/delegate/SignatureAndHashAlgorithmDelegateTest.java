/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import de.rub.nds.tlsattacker.core.config.delegate.SignatureAndHashAlgorithmDelegate;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmDelegateTest {

    private SignatureAndHashAlgorithmDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public SignatureAndHashAlgorithmDelegateTest() {
    }

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
        args[1] = "RSA-SHA512,DSA-SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(
                new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512)));
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(
                new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA512)));
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidSignatureHashAlgorithms() {
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA-STSDHA512,DsdfsdSA-SHA512";
        jcommander.parse(args);
    }

    /**
     * Test of setSignatureAndHashAlgorithms method, of class
     * SignatureAndHashAlgorithmDelegate.
     */
    @Test
    public void testSetSignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgoList = new LinkedList<>();
        signatureAndHashAlgoList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.ANONYMOUS, HashAlgorithm.SHA1));
        delegate.setSignatureAndHashAlgorithms(signatureAndHashAlgoList);
        assertTrue(delegate.getSignatureAndHashAlgorithms().contains(
                new SignatureAndHashAlgorithm(SignatureAlgorithm.ANONYMOUS, HashAlgorithm.SHA1)));
    }

    /**
     * Test of applyDelegate method, of class SignatureAndHashAlgorithmDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA-SHA512,DSA-SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getSupportedSignatureAndHashAlgorithms().contains(
                new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512)));
        assertTrue(config.getSupportedSignatureAndHashAlgorithms().contains(
                new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.SHA512)));
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }

}
