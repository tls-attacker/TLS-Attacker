/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.pq;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class PQUtils {

    public static MLKEMParameters getMLKEMParameters(NamedGroup namedGroup) {
        NamedGroup pqComponent = namedGroup;
        if (namedGroup.isHybridPQGroup()) {
            pqComponent = getPQGroup(namedGroup);
        }

        switch (pqComponent) {
            case MLKEM512:
                return MLKEMParameters.ml_kem_512;
            case MLKEM768:
                return MLKEMParameters.ml_kem_768;
            case MLKEM1024:
                return MLKEMParameters.ml_kem_1024;

            default:
                throw new IllegalArgumentException("Unsupported PQ group: " + namedGroup);
        }
    }

    // This method is only for the use with hybrid pq groups
    public static NamedGroup getClassicalGroup(NamedGroup namedGroup) {
        switch (namedGroup) {
            case X25519_MLKEM768:
                return NamedGroup.ECDH_X25519;
            case SECP256R1_MLKEM768:
                return NamedGroup.SECP256R1;
            case SECP384R1_MLKEM1024:
                return NamedGroup.SECP384R1;
            default:
                throw new IllegalArgumentException("Unsupported Hybrid PQ group: " + namedGroup);
        }
    }

    // This method is only for the use with hybrid pq groups
    public static NamedGroup getPQGroup(NamedGroup namedGroup) {
        switch (namedGroup) {
            case X25519_MLKEM768:
                return NamedGroup.MLKEM768;
            case SECP256R1_MLKEM768:
                return NamedGroup.MLKEM768;
            case SECP384R1_MLKEM1024:
                return NamedGroup.MLKEM1024;
            default:
                throw new IllegalArgumentException("Unsupported Hybrid PQ group: " + namedGroup);
        }
    }

    /**
     * Splits the keyShare for the respective hybrid pq group and stores the individual shares in
     * classicalKeyShare and pqKeyShare.
     *
     * @param namedGroup The namedGroup that should be used.
     * @param connectionEndType The connectionEndType whose keyShare should be split.
     * @param keyShare The key share to be split.
     */
    public static byte[][] splitKeyShare(
            NamedGroup namedGroup, ConnectionEndType connectionEndType, byte[] keyShare) {
        int splitAtIndex;
        switch (namedGroup) {
            case X25519_MLKEM768:
                /* The server sends a ciphertext of length 1088 bytes instead of the 1184 bytes public
                key share send by the client */
                splitAtIndex = (connectionEndType.equals(ConnectionEndType.CLIENT)) ? 1184 : 1088;
                return new byte[][] {
                    Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length),
                    Arrays.copyOfRange(keyShare, 0, splitAtIndex)
                };
            case SECP256R1_MLKEM768:
                splitAtIndex = 65;
                return new byte[][] {
                    Arrays.copyOfRange(keyShare, 0, splitAtIndex),
                    Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length)
                };
            case SECP384R1_MLKEM1024:
                splitAtIndex = 97;
                return new byte[][] {
                    Arrays.copyOfRange(keyShare, 0, splitAtIndex),
                    Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length)
                };
            default:
                throw new IllegalArgumentException("Unsupported Hybrid PQ group: " + namedGroup);
        }
    }

    /**
     * Concatenates the two key shares as specified in draft-ietf-tls-ecdhe-mlkem-04
     *
     * @param namedGroup The namedGroup that should be used
     * @param classicalKeyShare The classical key share to be used
     * @param pqKeyShare The post-quantum key share to be used
     * @return The concatenated key share
     * @param useStandardConcatenation The order in which to concatenate the shares. If true or
     *     standard logic is used.
     */
    public static byte[] concatenateHybridKeyShare(
            NamedGroup namedGroup,
            byte[] classicalKeyShare,
            byte[] pqKeyShare,
            Boolean useStandardConcatenation) {
        boolean standard = (useStandardConcatenation == null) ? true : useStandardConcatenation;
        if (standard) {
            if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
                return DataConverter.concatenate(pqKeyShare, classicalKeyShare);
            } else {
                return DataConverter.concatenate(classicalKeyShare, pqKeyShare);
            }
        } else {
            if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
                return DataConverter.concatenate(classicalKeyShare, pqKeyShare);
            } else {
                return DataConverter.concatenate(pqKeyShare, classicalKeyShare);
            }
        }
    }
}
