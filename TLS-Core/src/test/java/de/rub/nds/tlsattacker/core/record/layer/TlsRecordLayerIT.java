/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.layer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Random;
import java.util.stream.Stream;

public class TlsRecordLayerIT {

    private TlsRecordLayer layer;

    @BeforeEach
    public void setUp() {
        layer = new TlsRecordLayer(new TlsContext(Config.createConfig()));
    }

    public static Stream<byte[]> provideTestVectors() {
        Stream.Builder<byte[]> builder = Stream.builder();
        Random random = new Random(42);
        for (int i = 0; i < 1000; i++) {
            byte[] data = new byte[random.nextInt(1000)];
            random.nextBytes(data);
            builder.add(data);
        }
        return builder.build();
    }

    /**
     * Test of parseRecords method, of class TlsRecordLayer.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testParseRecords(byte[] data) {
        assertDoesNotThrow(() -> layer.parseRecordsSoftly(data));
    }
}
