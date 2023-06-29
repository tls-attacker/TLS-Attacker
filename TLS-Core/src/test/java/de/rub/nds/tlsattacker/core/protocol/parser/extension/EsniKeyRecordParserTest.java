/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EsniVersion;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class EsniKeyRecordParserTest {

    private Config config;
    private TlsContext tlsContext;

    @BeforeEach
    public void setUp() {
        this.config = Config.createConfig();
        this.tlsContext = new TlsContext(config);
        this.tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000"),
                        EsniVersion.DRAFT_2,
                        ArrayConverter.hexStringToByteArray("00124b2a"),
                        List.of(
                                new KeyShareStoreEntry(
                                        NamedGroup.ECDH_X25519,
                                        ArrayConverter.hexStringToByteArray(
                                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"))),
                        List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                        260,
                        ArrayConverter.hexStringToByteArray("000000005dcc3a45"),
                        ArrayConverter.hexStringToByteArray("000000005dda1205"),
                        0,
                        null),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac5818118633259444120004130113020104000000005dcc3a45000000005dda12050000"),
                        EsniVersion.DRAFT_2,
                        ArrayConverter.hexStringToByteArray("00124b2a"),
                        List.of(
                                new KeyShareStoreEntry(
                                        NamedGroup.ECDH_X25519,
                                        ArrayConverter.hexStringToByteArray(
                                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"))),
                        List.of(
                                CipherSuite.TLS_AES_128_GCM_SHA256,
                                CipherSuite.TLS_AES_256_GCM_SHA384),
                        260,
                        ArrayConverter.hexStringToByteArray("000000005dcc3a45"),
                        ArrayConverter.hexStringToByteArray("000000005dda1205"),
                        0,
                        null),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "ff0100124b2a0046001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412001E001Efa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325940004130113020104000000005dcc3a45000000005dda12050000"),
                        EsniVersion.DRAFT_2,
                        ArrayConverter.hexStringToByteArray("00124b2a"),
                        List.of(
                                new KeyShareStoreEntry(
                                        NamedGroup.ECDH_X25519,
                                        ArrayConverter.hexStringToByteArray(
                                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412")),
                                new KeyShareStoreEntry(
                                        NamedGroup.ECDH_X448,
                                        ArrayConverter.hexStringToByteArray(
                                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac58181186332594"))),
                        List.of(
                                CipherSuite.TLS_AES_128_GCM_SHA256,
                                CipherSuite.TLS_AES_256_GCM_SHA384),
                        260,
                        ArrayConverter.hexStringToByteArray("000000005dcc3a45"),
                        ArrayConverter.hexStringToByteArray("000000005dda1205"),
                        0,
                        null),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050014ffce0010a7284c9a52f15c13644b947261774657"),
                        EsniVersion.DRAFT_2,
                        ArrayConverter.hexStringToByteArray("00124b2a"),
                        List.of(
                                new KeyShareStoreEntry(
                                        NamedGroup.ECDH_X25519,
                                        ArrayConverter.hexStringToByteArray(
                                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"))),
                        List.of(CipherSuite.TLS_AES_128_GCM_SHA256),
                        260,
                        ArrayConverter.hexStringToByteArray("000000005dcc3a45"),
                        ArrayConverter.hexStringToByteArray("000000005dda1205"),
                        1,
                        ArrayConverter.hexStringToByteArray("a7284c9a52f15c13644b947261774657")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedRecordBytes,
            EsniVersion expectedEsniVersion,
            byte[] expectedChecksum,
            List<KeyShareStoreEntry> expectedKeys,
            List<CipherSuite> expectedCipherSuites,
            int expectedPaddedLength,
            byte[] expectedNotBefore,
            byte[] expectedNotAfter,
            int expectedExtensionsLength,
            byte[] expectedExtensionNonce) {
        EsniKeyRecordParser parser =
                new EsniKeyRecordParser(new ByteArrayInputStream(providedRecordBytes), tlsContext);
        EsniKeyRecord esniKeyRecord = new EsniKeyRecord();
        parser.parse(esniKeyRecord);

        assertArrayEquals(
                expectedEsniVersion.getDnsKeyRecordVersion().getByteValue(),
                esniKeyRecord.getVersion().getByteValue());
        assertArrayEquals(expectedChecksum, esniKeyRecord.getChecksum());
        assertEquals(expectedKeys.size(), esniKeyRecord.getKeys().size());
        for (int i = 0; i < expectedKeys.size(); i++) {
            assertEquals(expectedKeys.get(i).getGroup(), esniKeyRecord.getKeys().get(i).getGroup());
            assertArrayEquals(
                    expectedKeys.get(i).getPublicKey(),
                    esniKeyRecord.getKeys().get(i).getPublicKey());
        }
        assertEquals(expectedCipherSuites.size(), esniKeyRecord.getCipherSuites().size());
        for (int i = 0; i < expectedCipherSuites.size(); i++) {
            assertEquals(expectedCipherSuites.get(i), esniKeyRecord.getCipherSuites().get(i));
        }
        assertEquals(expectedPaddedLength, esniKeyRecord.getPaddedLength());
        assertArrayEquals(
                expectedNotBefore,
                ArrayConverter.longToBytes(
                        esniKeyRecord.getNotBefore(), ExtensionByteLength.ESNI_RECORD_NOT_BEFORE));
        assertArrayEquals(
                expectedNotAfter,
                ArrayConverter.longToBytes(
                        esniKeyRecord.getNotAfter(), ExtensionByteLength.ESNI_RECORD_NOT_AFTER));
        assertEquals(expectedExtensionsLength, esniKeyRecord.getExtensions().size());
        if (expectedExtensionsLength > 0) {
            // TODO: Find a more generic way to assert ESNI key record extensions
            EncryptedServerNameIndicationExtensionMessage resultExtension =
                    (EncryptedServerNameIndicationExtensionMessage)
                            esniKeyRecord.getExtensions().get(0);
            assertArrayEquals(expectedExtensionNonce, resultExtension.getServerNonce().getValue());
        }
    }
}
