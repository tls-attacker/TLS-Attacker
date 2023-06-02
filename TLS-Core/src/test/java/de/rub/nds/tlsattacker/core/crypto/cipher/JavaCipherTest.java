/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class JavaCipherTest {

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @EnumSource(
            value = CipherAlgorithm.class,
            names = {
                "(AES|ARIA|CAMELLIA)_(128|256)_(CBC|GCM)",
                "DES_(EDE_)?CBC",
                "(IDEA|RC2|RC4)_128",
                "SEED_CBC"
            },
            mode = EnumSource.Mode.MATCH_ANY)
    public void testInstantiationDoesNotThrow(CipherAlgorithm providedCipherAlgorithm) {
        byte[] key = new byte[providedCipherAlgorithm.getKeySize()];
        assertDoesNotThrow(() -> new JavaCipher(providedCipherAlgorithm, key, false));
    }
}
