/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class CustomECPrivateKeyTest {

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Test of getParams method, of class CustomECPrivateKey. */
    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            // TODO: Add BRAINPOOL curves once ASN.1-Tool is integrated
            names = {"^(SECT|SECP).*"},
            mode = EnumSource.Mode.MATCH_ANY)
    public void testGetParams(NamedGroup providedNamedGroup) {
        CustomECPrivateKey key = new CustomECPrivateKey(BigInteger.TEN, providedNamedGroup);
        ECParameterSpec params = key.getParams();
        assertNotNull(params);
    }
}
