/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PlainPaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.TrippleVector;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 *
 */
public class ShortPaddingGenerator extends PaddingVectorGenerator {

    /**
     * Default length of the encrypted data (app + mac + padding). This value
     * was chosen to cover all the possible MAC algorithms (with SHA384 which
     * has a 48 byte long output length) so that two full padding blocks can be
     * inserted.
     */
    static final int DEFAULT_CIPHERTEXT_LENGTH = 80;
    /**
     * Default padding length for the construction of modified encrypted
     * plaintexts
     */
    static final int DEFAULT_PADDING_LENGTH = 4;

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        vectorList.addAll(createBasicMacVectors(suite, version));
        vectorList.addAll(createMissingMacByteVectors(suite, version));
        vectorList.addAll(createOnlyPaddingVectors(suite, version));
        vectorList.addAll(createClassicModifiedPadding(suite, version));
        return vectorList;
    }

    /**
     * Create Vectors with Valid Padding but invalid Mac on 3 different
     * Positions
     *
     * @param suite
     * @param version
     * @return
     */
    List<PaddingVector> createBasicMacVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        int i = 1;
        for (ByteArrayXorModification modification : createFlippedModifications(macSize)) {
            vectorList.add(new TrippleVector("BasicMac-" + modification.getStartPosition() + "-"
                    + ArrayConverter.bytesToHexString(modification.getXor()), "BasicMac" + i,
                    new ByteArrayExplicitValueModification(new byte[DEFAULT_CIPHERTEXT_LENGTH - macSize
                            - DEFAULT_PADDING_LENGTH]), modification, null));
            i++;
        }
        return vectorList;
    }

    /**
     * Creates vectors where the first mac byte is missing
     *
     * @param suite
     * @param version
     * @return
     */
    List<PaddingVector> createMissingMacByteVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        byte[] padding = createPaddingBytes(DEFAULT_CIPHERTEXT_LENGTH - macSize);
        // Missing first MAC byte because of overlong valid padding
        vectorList.add(new TrippleVector("MissingMacByteFirst", "MissingMacByteFirst",
                new ByteArrayExplicitValueModification(new byte[0]), new ByteArrayDeleteModification(0, 1),
                new ByteArrayExplicitValueModification(padding)));
        // Missing last MAC byte because of overlong valid padding
        padding = createPaddingBytes(DEFAULT_CIPHERTEXT_LENGTH - macSize);

        vectorList.add(new TrippleVector("MissingMacByteLast", "MissingMacByteLast",
                new ByteArrayExplicitValueModification(new byte[0]), new ByteArrayDeleteModification((macSize - 1), 1),
                new ByteArrayExplicitValueModification(padding)));
        return vectorList;
    }

    List<PaddingVector> createOnlyPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        byte[] plain = createPaddingBytes(DEFAULT_CIPHERTEXT_LENGTH - 1);
        vectorList.add(createVectorWithPlainData("Plain XF (0xXF=#padding bytes)", "PlainOnlyPadding", plain));
        plain = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, };
        vectorList.add(createVectorWithPlainData("Plain FF", "PlainTooMuchPadding", plain));
        return vectorList;
    }

    List<PaddingVector> createClassicModifiedPadding(CipherSuite suite, ProtocolVersion version) {
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        int paddingValue = DEFAULT_CIPHERTEXT_LENGTH - macSize - 1;
        int applicationLength = 0;
        List<PaddingVector> vectorList = createClassicModifiedPaddingWithValidMAC(applicationLength, paddingValue, "0");
        vectorList.addAll(createClassicModifiedPaddingWithInvalidMAC(applicationLength, paddingValue, "0"));

        paddingValue = 6;
        applicationLength = DEFAULT_CIPHERTEXT_LENGTH - macSize - 7;
        vectorList.addAll(createClassicModifiedPaddingWithValidMAC(applicationLength, paddingValue, ""));
        vectorList.addAll(createClassicModifiedPaddingWithInvalidMAC(applicationLength, paddingValue, ""));

        return vectorList;
    }

    private List<PaddingVector> createClassicModifiedPaddingWithValidMAC(int applicationLength, int paddingValue,
            String suffix) {
        List<PaddingVector> vectorList = new LinkedList<>();
        // valid mac
        byte[] padding = createPaddingBytes(paddingValue);
        padding[0] ^= 0x80; // flip first padding byte highest bit
        vectorList.add(new TrippleVector("InvPadValMac-[0]-" + applicationLength + "-" + paddingValue,
                "InvPadValMacStart" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                null, new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(paddingValue);
        padding[paddingValue / 2] ^= 0x8; // flip middle padding byte
        // middle bit
        vectorList.add(new TrippleVector("InvPadValMac-[" + (paddingValue / 2) + "]-" + applicationLength + "-"
                + paddingValue, "InvPadValMacMid" + suffix, new ByteArrayExplicitValueModification(
                new byte[applicationLength]), null, new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(paddingValue);
        padding[padding.length - 1] ^= 0x01; // flip last padding byte lowest
        // bit
        vectorList.add(new TrippleVector("InvPadValMac-[last]-" + applicationLength + "-" + paddingValue,
                "InvPadValMacEnd" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]), null,
                new ByteArrayExplicitValueModification(padding)));
        return vectorList;
    }

    private List<PaddingVector> createClassicModifiedPaddingWithInvalidMAC(int applicationLength, int paddingValue,
            String suffix) {
        List<PaddingVector> vectorList = new LinkedList<>();
        // invalid mac
        byte[] padding = createPaddingBytes(paddingValue);
        vectorList.add(new TrippleVector("ValPadInvMac-[0]-" + applicationLength + "-" + paddingValue,
                "ValPadInvMacStart" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                new ByteArrayXorModification(new byte[] { 0x01 }, 0), new ByteArrayExplicitValueModification(padding)));

        padding = createPaddingBytes(paddingValue);
        vectorList.add(new TrippleVector("ValPadInvMac-[" + (8) + "]-" + applicationLength + "-" + paddingValue,
                "ValPadInvMacMid" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                new ByteArrayXorModification(new byte[] { 0x08 }, 8), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(paddingValue);

        vectorList.add(new TrippleVector("ValPadInvMac-[15]-" + applicationLength + "-" + paddingValue,
                "ValPadInvMacEnd" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                new ByteArrayXorModification(new byte[] { (byte) 0x80 }, 15), new ByteArrayExplicitValueModification(
                        padding)));
        padding = createPaddingBytes(paddingValue);

        padding[0] ^= 0x80; // flip first padding byte highest bit
        vectorList.add(new TrippleVector("InvPadInvMac-[0]-" + applicationLength + "-" + paddingValue,
                "InvPadInvMacStart" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                new ByteArrayXorModification(new byte[] { 0x01 }, 0), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(paddingValue);
        padding[paddingValue / 2] ^= 0x8; // flip middle padding byte
        // middle bit
        vectorList.add(new TrippleVector("InvPadInvMac-[" + (paddingValue / 2) + "]-" + applicationLength + "-"
                + paddingValue, "InvPadInvMacMid" + suffix, new ByteArrayExplicitValueModification(
                new byte[applicationLength]), new ByteArrayXorModification(new byte[] { 0x01 }, 0),
                new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(paddingValue);
        padding[padding.length - 1] ^= 0x01; // flip last padding lowest first
        // bit
        vectorList.add(new TrippleVector("InvPadInvMac-[last]-" + applicationLength + "-" + paddingValue,
                "InvPadInvMacEnd" + suffix, new ByteArrayExplicitValueModification(new byte[applicationLength]),
                new ByteArrayXorModification(new byte[] { 0x01 }, 0), new ByteArrayExplicitValueModification(padding)));
        return vectorList;
    }

    List<ByteArrayXorModification> createFlippedModifications(int byteLength) {
        List<ByteArrayXorModification> modificationList = new LinkedList<>();
        modificationList.add(new ByteArrayXorModification(new byte[] { 0x01 }, byteLength - 1)); // Last
        // Byte / lowest bit
        modificationList.add(new ByteArrayXorModification(new byte[] { 0x08 }, byteLength / 2)); // Some
        // Byte / middle bit
        modificationList.add(new ByteArrayXorModification(new byte[] { (byte) 0x80 }, 0)); // first
        // Byte / highest bit
        return modificationList;
    }

    private PaddingVector createVectorWithPlainData(String name, String identifier, byte[] plain) {
        return new PlainPaddingVector(name, identifier,
                (ByteArrayExplicitValueModification) ByteArrayModificationFactory.explicitValue(plain));
    }
}
