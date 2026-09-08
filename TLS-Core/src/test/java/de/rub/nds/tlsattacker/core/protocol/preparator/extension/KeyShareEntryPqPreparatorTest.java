/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.protocol.crypto.key.MlKemPrivateKey;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class KeyShareEntryPqPreparatorTest {

    private static final BigInteger CLASSICAL_PRIVATE_KEY =
            new BigInteger("03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF", 16);

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testPrepareClientPqKeyShare(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, null);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] publicKey = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT),
                publicKey.length);
        assertEquals(publicKey.length, (int) entry.getPublicKeyLength().getValue());
        assertArrayEquals(entry.getMLKEMPublicKey().getValue(), publicKey);
        assertArrayEquals(namedGroup.getValue(), entry.getGroup().getValue());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testPrepareClientPqKeyShareStoresKeyPairInContext(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, null);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        assertArrayEquals(
                entry.getPublicKey().getValue(),
                context.getClientMLKEMPublicKeys().get(namedGroup).getEncapsulationKey());
        assertArrayEquals(
                entry.getMLKEMPrivateKey(),
                context.getClientMLKEMPrivateKeys().get(namedGroup).getDecapsulationKey());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testPrepareClientHybridKeyShare(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] publicKey = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getEcPublicKeyLength(namedGroup)
                        + PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT),
                publicKey.length);
        assertEquals(publicKey.length, (int) entry.getPublicKeyLength().getValue());

        byte[][] splitKeyShare =
                PQUtils.splitKeyShare(namedGroup, ConnectionEndType.CLIENT, publicKey);
        assertArrayEquals(expectedClassicalPublicKey(context, namedGroup), splitKeyShare[0]);
        assertArrayEquals(entry.getMLKEMPublicKey().getValue(), splitKeyShare[1]);
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testPrepareClientHybridKeyShareKeysContextByHybridGroup(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        assertNotNull(context.getClientMLKEMPrivateKeys().get(namedGroup));
        assertNotNull(context.getClientMLKEMPublicKeys().get(namedGroup));
        assertNull(
                context.getClientMLKEMPrivateKeys()
                        .get(namedGroup.getHybridPostQuantumNamedGroup()));
        assertNull(
                context.getClientMLKEMPublicKeys()
                        .get(namedGroup.getHybridPostQuantumNamedGroup()));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testPrepareServerPqKeyShare(NamedGroup namedGroup) {
        ClientKeyPair clientKeyPair = generateClientKeyPair(namedGroup);
        TlsContext context =
                serverContextWithClientKeyShare(namedGroup, clientKeyPair.encapsulationKey);
        KeyShareEntry entry = new KeyShareEntry(namedGroup, null);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] ciphertext = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                ciphertext.length);
        assertArrayEquals(ciphertext, context.getServerMLKEMCiphertext());
        assertArrayEquals(
                KeyShareCalculator.mlkemDecaps(namedGroup, clientKeyPair.privateKey, ciphertext),
                context.getPQSharedSecret());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testPrepareServerHybridKeyShare(NamedGroup namedGroup) {
        ClientKeyPair clientKeyPair = generateClientKeyPair(namedGroup);
        TlsContext context =
                serverContextWithClientKeyShare(
                        namedGroup,
                        PQUtils.concatenateHybridKeyShare(
                                namedGroup,
                                filled(PQUtils.getEcPublicKeyLength(namedGroup), (byte) 0x04),
                                clientKeyPair.encapsulationKey));
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] publicKey = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getEcPublicKeyLength(namedGroup)
                        + PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                publicKey.length);

        byte[][] splitKeyShare =
                PQUtils.splitKeyShare(namedGroup, ConnectionEndType.SERVER, publicKey);
        assertArrayEquals(expectedClassicalPublicKey(context, namedGroup), splitKeyShare[0]);
        assertArrayEquals(splitKeyShare[1], context.getServerMLKEMCiphertext());
        assertArrayEquals(
                KeyShareCalculator.mlkemDecaps(
                        namedGroup, clientKeyPair.privateKey, splitKeyShare[1]),
                context.getPQSharedSecret());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testDefaultServerMlKemCiphertextOverridesWireBytesOnly(NamedGroup namedGroup) {
        ClientKeyPair clientKeyPair = generateClientKeyPair(namedGroup);
        byte[] clientKeyShare =
                namedGroup.isHybridPQGroup()
                        ? PQUtils.concatenateHybridKeyShare(
                                namedGroup,
                                filled(PQUtils.getEcPublicKeyLength(namedGroup), (byte) 0x04),
                                clientKeyPair.encapsulationKey)
                        : clientKeyPair.encapsulationKey;
        TlsContext context = serverContextWithClientKeyShare(namedGroup, clientKeyShare);
        byte[] override =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                        (byte) 0x22);
        context.getConfig().setDefaultServerMLKEMCiphertext(override);
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] sentCiphertext =
                namedGroup.isHybridPQGroup()
                        ? PQUtils.splitKeyShare(
                                namedGroup,
                                ConnectionEndType.SERVER,
                                entry.getPublicKey().getValue())[1]
                        : entry.getPublicKey().getValue();
        assertArrayEquals(override, sentCiphertext);
        assertArrayEquals(override, context.getServerMLKEMCiphertext());
        assertEquals(32, context.getPQSharedSecret().length);
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {
                "MLKEM512",
                "MLKEM768",
                "MLKEM1024",
                "X25519_MLKEM768",
                "SECP256R1_MLKEM768",
                "SECP384R1_MLKEM1024"
            })
    public void testConfiguredDecapsulationKeyIsUsedForClientKeyShare(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        byte[] decapsulationKey = generateDecapsulationKey(namedGroup);
        setConfiguredDecapsulationKey(context, namedGroup, decapsulationKey);
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        MlKemPrivateKey expected =
                new MlKemPrivateKey(
                        KeyShareCalculator.getMlKemParameters(namedGroup), decapsulationKey);
        assertArrayEquals(decapsulationKey, entry.getMLKEMPrivateKey());
        assertArrayEquals(expected.getEncapsulationKey(), entry.getMLKEMPublicKey().getValue());
        assertArrayEquals(expected.getEncapsulationKey(), sentPqKeyShare(namedGroup, entry));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {
                "MLKEM512",
                "MLKEM768",
                "MLKEM1024",
                "X25519_MLKEM768",
                "SECP256R1_MLKEM768",
                "SECP384R1_MLKEM1024"
            })
    public void testConfiguredDecapsulationKeyMakesClientKeyShareStable(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        setConfiguredDecapsulationKey(context, namedGroup, generateDecapsulationKey(namedGroup));

        assertArrayEquals(
                prepareInContext(context, namedGroup), prepareInContext(context, namedGroup));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {
                "MLKEM512",
                "MLKEM768",
                "MLKEM1024",
                "X25519_MLKEM768",
                "SECP256R1_MLKEM768",
                "SECP384R1_MLKEM1024"
            })
    public void testClearedDecapsulationKeyFallsBackToGeneratedKeyShare(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        setConfiguredDecapsulationKey(context, namedGroup, new byte[0]);

        assertFalse(
                Arrays.equals(
                        prepareInContext(context, namedGroup),
                        prepareInContext(context, namedGroup)));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "X25519_MLKEM768"})
    public void testConfiguredDecapsulationKeyRoundTripsThroughEncapsulation(
            NamedGroup namedGroup) {
        TlsContext context = clientContext();
        byte[] decapsulationKey = generateDecapsulationKey(namedGroup);
        setConfiguredDecapsulationKey(context, namedGroup, decapsulationKey);
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        MlKemEncapsulation encapsulation =
                KeyShareCalculator.mlkemEncaps(
                        namedGroup, entry.getMLKEMPublicKey().getValue(), new SecureRandom());
        assertArrayEquals(
                encapsulation.getSharedSecret(),
                KeyShareCalculator.mlkemDecaps(
                        namedGroup,
                        entry.getMLKEMPrivateKeyContainer(),
                        encapsulation.getCiphertext()));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {
                "MLKEM512",
                "MLKEM768",
                "MLKEM1024",
                "X25519_MLKEM768",
                "SECP256R1_MLKEM768",
                "SECP384R1_MLKEM1024"
            })
    public void testDefaultConfigUsesHardCodedDecapsulationKey(NamedGroup namedGroup) {
        TlsContext context = clientContext();
        byte[] configuredKey =
                context.getConfig()
                        .getDefaultClientMlKemKeyParameters(
                                KeyShareCalculator.getMlKemParameters(namedGroup));
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        assertEquals(
                KeyShareCalculator.getMlKemParameters(namedGroup).getDecapsulationKeySizeBytes(),
                configuredKey.length);
        assertArrayEquals(configuredKey, entry.getMLKEMPrivateKey());

        MlKemEncapsulation encapsulation =
                KeyShareCalculator.mlkemEncaps(
                        namedGroup, entry.getMLKEMPublicKey().getValue(), new SecureRandom());
        assertArrayEquals(
                encapsulation.getSharedSecret(),
                KeyShareCalculator.mlkemDecaps(
                        namedGroup,
                        entry.getMLKEMPrivateKeyContainer(),
                        encapsulation.getCiphertext()));
    }

    private static byte[] prepareInContext(TlsContext context, NamedGroup namedGroup) {
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);
        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();
        return entry.getPublicKey().getValue();
    }

    private static void setConfiguredDecapsulationKey(
            TlsContext context, NamedGroup namedGroup, byte[] decapsulationKey) {
        switch (KeyShareCalculator.getMlKemParameters(namedGroup)) {
            case ML_KEM_512:
                context.getConfig().setDefaultClientMlKem512KeyParameters(decapsulationKey);
                break;
            case ML_KEM_768:
                context.getConfig().setDefaultClientMlKem768KeyParameters(decapsulationKey);
                break;
            case ML_KEM_1024:
                context.getConfig().setDefaultClientMlKem1024KeyParameters(decapsulationKey);
                break;
        }
    }

    private static byte[] generateDecapsulationKey(NamedGroup namedGroup) {
        KeyShareEntry entry = new KeyShareEntry();
        KeyShareCalculator.createMLKEMKeyShare(namedGroup, entry, new SecureRandom());
        return entry.getMLKEMPrivateKey();
    }

    private static byte[] sentPqKeyShare(NamedGroup namedGroup, KeyShareEntry entry) {
        if (namedGroup.isHybridPQGroup()) {
            return PQUtils.splitKeyShare(
                    namedGroup, ConnectionEndType.CLIENT, entry.getPublicKey().getValue())[1];
        }
        return entry.getPublicKey().getValue();
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testPrepareServerPqKeyShareWithoutClientKeyShareUsesDefaultKey(
            NamedGroup namedGroup) {
        TlsContext context = serverContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, null);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] ciphertext = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                ciphertext.length);
        assertArrayEquals(
                KeyShareCalculator.mlkemDecaps(
                        namedGroup, defaultClientPrivateKey(context, namedGroup), ciphertext),
                context.getPQSharedSecret());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testPrepareServerHybridKeyShareWithoutClientKeyShareUsesDefaultKey(
            NamedGroup namedGroup) {
        TlsContext context = serverContext();
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);

        new KeyShareEntryPreparator(context.getChooser(), entry).prepare();

        byte[] publicKey = entry.getPublicKey().getValue();
        assertEquals(
                PQUtils.getEcPublicKeyLength(namedGroup)
                        + PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                publicKey.length);
        byte[][] splitKeyShare =
                PQUtils.splitKeyShare(namedGroup, ConnectionEndType.SERVER, publicKey);
        assertArrayEquals(
                KeyShareCalculator.mlkemDecaps(
                        namedGroup, defaultClientPrivateKey(context, namedGroup), splitKeyShare[1]),
                context.getPQSharedSecret());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "X25519_MLKEM768"})
    public void testPrepareServerKeyShareWithoutClientKeyShareAndClearedDefaultThrows(
            NamedGroup namedGroup) {
        TlsContext context = serverContext();
        setConfiguredDecapsulationKey(context, namedGroup, new byte[0]);
        KeyShareEntry entry = new KeyShareEntry(namedGroup, CLASSICAL_PRIVATE_KEY);
        KeyShareEntryPreparator preparator =
                new KeyShareEntryPreparator(context.getChooser(), entry);

        assertThrows(PreparationException.class, preparator::prepare);
    }

    private static MlKemPrivateKey defaultClientPrivateKey(
            TlsContext context, NamedGroup namedGroup) {
        MlKemParameters parameters = KeyShareCalculator.getMlKemParameters(namedGroup);
        return new MlKemPrivateKey(
                parameters, context.getConfig().getDefaultClientMlKemKeyParameters(parameters));
    }

    private static ClientKeyPair generateClientKeyPair(NamedGroup namedGroup) {
        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMLKEMKeyShare(namedGroup, clientEntry, new SecureRandom());
        return new ClientKeyPair(
                clientEntry.getMLKEMPublicKey().getValue(),
                clientEntry.getMLKEMPrivateKeyContainer());
    }

    private static class ClientKeyPair {

        private final byte[] encapsulationKey;

        private final MlKemPrivateKey privateKey;

        ClientKeyPair(byte[] encapsulationKey, MlKemPrivateKey privateKey) {
            this.encapsulationKey = encapsulationKey;
            this.privateKey = privateKey;
        }
    }

    private byte[] expectedClassicalPublicKey(TlsContext context, NamedGroup namedGroup) {
        return KeyShareCalculator.createKeyAgreementPublicKey(
                namedGroup.getHybridPostQuantumClassicNamedGroup(),
                CLASSICAL_PRIVATE_KEY,
                context.getConfig().getDefaultSelectedPointFormat());
    }

    private TlsContext clientContext() {
        return new Context(new State(new Config()), new OutboundConnection()).getTlsContext();
    }

    private TlsContext serverContext() {
        return new Context(new State(new Config()), new InboundConnection()).getTlsContext();
    }

    private TlsContext serverContextWithClientKeyShare(NamedGroup namedGroup, byte[] publicKey) {
        TlsContext context = serverContext();
        context.setClientKeyShareStoreEntryList(
                Collections.singletonList(new KeyShareStoreEntry(namedGroup, publicKey)));
        return context;
    }

    private static byte[] filled(int length, byte value) {
        byte[] array = new byte[length];
        Arrays.fill(array, value);
        return array;
    }
}
