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
import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;

public class PQUtils {

    public static int getPQKeyShareLength(
            NamedGroup namedGroup, ConnectionEndType connectionEndType) {

        NamedGroup pqGroup = namedGroup.getAnyInvolvedPqGroup();
        if (pqGroup.isMlKemGroup()) {
            MlKemParameters parameters = (MlKemParameters) pqGroup.getAsymmetricParameters();
            if (connectionEndType == ConnectionEndType.CLIENT) {
                // we parse the encapsulation key
                return parameters.getEncapsulationKeySizeBytes();
            } else {
                // we parse the ciphertext
                return parameters.getCiphertextSizeBytes();
            }
        }
        throw new IllegalArgumentException("Unsupported Hybrid PQ group: " + namedGroup);
    }

    public static int getEcPublicKeyLength(NamedGroup namedGroup) {
        NamedGroup pqGroup = namedGroup.getHybridPostQuantumClassicNamedGroup();
        if (!pqGroup.isEcGroup()) {
            throw new IllegalArgumentException("Group is not an elliptic curve");
        }

        if (pqGroup.isMontgomery()) {
            return pqGroup.getGroupParameters().getElementSizeBytes();
        } else {
            return pqGroup.getGroupParameters().getElementSizeBytes() * 2 + 1;
        }
    }

    /**
     * Returns whether the post-quantum share precedes the classical share in the concatenations of
     * the given hybrid group. Early group definitions implemented this.
     *
     * @param namedGroup The namedGroup that should be used.
     * @return True if the post-quantum share comes first.
     */
    public static boolean isPqShareFirst(NamedGroup namedGroup) {
        return namedGroup == NamedGroup.X25519_MLKEM768 || namedGroup == NamedGroup.MLKEM512_X25519;
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
        if (!namedGroup.isHybridPQGroup()) {
            throw new IllegalArgumentException("Unsupported Hybrid PQ group: " + namedGroup);
        }
        if (isPqShareFirst(namedGroup)) {
            int splitAtIndex = getPQKeyShareLength(namedGroup, connectionEndType);
            return new byte[][] {
                Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length),
                Arrays.copyOfRange(keyShare, 0, splitAtIndex)
            };
        }
        int splitAtIndex = getEcPublicKeyLength(namedGroup);
        return new byte[][] {
            Arrays.copyOfRange(keyShare, 0, splitAtIndex),
            Arrays.copyOfRange(keyShare, splitAtIndex, keyShare.length)
        };
    }

    /**
     * Concatenates the two key shares as specified in RFC 10024, draft-rosomakho-tls-ecdhe-mlkem512
     * and draft-yang-tls-hybrid-sm2-mlkem
     *
     * @param namedGroup The namedGroup that should be used
     * @param classicalKeyShare The classical key share to be used
     * @param pqKeyShare The post-quantum key share to be used standard logic is used.
     * @return The concatenated key share
     */
    public static byte[] concatenateHybridKeyShare(
            NamedGroup namedGroup, byte[] classicalKeyShare, byte[] pqKeyShare) {
        if (isPqShareFirst(namedGroup)) {
            return DataConverter.concatenate(pqKeyShare, classicalKeyShare);
        } else {
            return DataConverter.concatenate(classicalKeyShare, pqKeyShare);
        }
    }
}
