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

import de.rub.nds.tlsattacker.core.config.Config;
import java.security.*;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CertificateDelegateTest extends AbstractDelegateTest<CertificateDelegate> {

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        super.setUp(new CertificateDelegate());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = new Config();
        Config config2 = new Config();
        delegate.applyDelegate(config);
        assertTrue(
                EqualsBuilder.reflectionEquals(
                        config, config2, "certificateChainConfig", "iceConfig"));
    }
}
