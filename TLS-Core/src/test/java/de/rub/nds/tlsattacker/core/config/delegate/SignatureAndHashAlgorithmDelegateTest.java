/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SignatureAndHashAlgorithmDelegateTest
        extends AbstractDelegateTest<SignatureAndHashAlgorithmDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new SignatureAndHashAlgorithmDelegate());
    }

    /** Test of getSignatureAndHashAlgorithms method, of class SignatureAndHashAlgorithmDelegate. */
    @Test
    public void testGetSignatureAndHashAlgorithms() {
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_SHA512,DSA_SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        assertTrue(
                delegate.getSignatureAndHashAlgorithms()
                        .contains(SignatureAndHashAlgorithm.RSA_SHA512));
        assertTrue(
                delegate.getSignatureAndHashAlgorithms()
                        .contains(SignatureAndHashAlgorithm.DSA_SHA512));
    }

    @Test
    public void testGetInvalidSignatureHashAlgorithms() {
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_STSDHA512,DsdfsdSA_SHA512";
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setSignatureAndHashAlgorithms method, of class SignatureAndHashAlgorithmDelegate. */
    @Test
    public void testSetSignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgoList = new LinkedList<>();
        signatureAndHashAlgoList.add(SignatureAndHashAlgorithm.ANONYMOUS_SHA1);
        delegate.setSignatureAndHashAlgorithms(signatureAndHashAlgoList);
        assertTrue(
                delegate.getSignatureAndHashAlgorithms()
                        .contains(SignatureAndHashAlgorithm.ANONYMOUS_SHA1));
    }

    /** Test of applyDelegate method, of class SignatureAndHashAlgorithmDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-signature_hash_algo";
        args[1] = "RSA_SHA512,DSA_SHA512";
        delegate.setSignatureAndHashAlgorithms(null);
        jcommander.parse(args);
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        assertFalse(config.isAddSignatureAndHashAlgorithmsExtension());
        delegate.applyDelegate(config);
        assertTrue(config.isAddSignatureAndHashAlgorithmsExtension());
        assertTrue(
                config.getDefaultClientSupportedSignatureAndHashAlgorithms()
                        .contains(SignatureAndHashAlgorithm.RSA_SHA512));
        assertTrue(
                config.getDefaultClientSupportedSignatureAndHashAlgorithms()
                        .contains(SignatureAndHashAlgorithm.DSA_SHA512));
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(
                EqualsBuilder.reflectionEquals(
                        config, config2, "keyStore", "ourCertificate")); // little
        // ugly
    }
}
