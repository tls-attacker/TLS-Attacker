/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.pq;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class PQUtils {

    public static MLKEMParameters getMLKEMParameters(NamedGroup namedGroup) {
        switch (namedGroup) {
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
     * @param keyShare The key share to be split.
     */
    public static byte[][] splitKeyShare(NamedGroup namedGroup, byte[] keyShare) {
        int splitAtIndex;
        switch (namedGroup) {
            case X25519_MLKEM768 -> splitAtIndex = 1088;
            case SECP256R1_MLKEM768 -> splitAtIndex = 65;
            case SECP384R1_MLKEM1024 -> splitAtIndex = 97;
            default ->
                    throw new IllegalArgumentException(
                            "Unsupported Hybrid PQ group: " + namedGroup);
        }

        return new byte[][] {
            Arrays.copyOfRange(keyShare, 0, splitAtIndex),
            Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length)
        };
    }
}
