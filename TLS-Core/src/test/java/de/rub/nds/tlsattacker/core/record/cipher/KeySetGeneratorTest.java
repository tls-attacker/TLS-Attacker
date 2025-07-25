/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeySetGeneratorTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new Context(new State(new Config()), new InboundConnection()).getTlsContext();
    }

    public static Stream<Arguments> provideTestVectors() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            for (ProtocolVersion version : ProtocolVersion.values()) {
                if (version == ProtocolVersion.SSL2
                        || version == ProtocolVersion.SSL3
                        || (!suite.isTls13() && version.is13())) {
                    continue;
                }
                builder.add(Arguments.of(version, suite));
            }
        }
        return builder.build();
    }

    /**
     * Test that for each implemented CipherSuite/ProtocolVersion a KeySet can be generated without
     * throwing an exception
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    @Tag(TestCategories.SLOW_TEST)
    public void testGenerateKeySet(ProtocolVersion protocolVersion, CipherSuite cipherSuite)
            throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedCipherSuite(cipherSuite);
        context.setSelectedProtocolVersion(protocolVersion);
        assertNotNull(KeyDerivator.generateKeySet(context));
    }
}
