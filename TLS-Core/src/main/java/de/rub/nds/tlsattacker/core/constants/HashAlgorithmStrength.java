/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * Wrapper mapping {@link HashAlgorithm}s to their security strength according to a specification.
 * <p>
 * A security strength is a number associated with the amount of work (i.e., the number of operations) that is required
 * to break a cryptographic algorithm or system.
 * <p>
 * Commonly used security strengths: 80, 112, 128, 192, and 256 bits.
 */
public enum HashAlgorithmStrength {

    /**
     * Strength according to NIST.SP.800-57pt1r5.
     *
     * @see <a href=
     *      "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf">NIST.SP.800-57pt1r5</a>
     */
    NIST(new HashMap<HashAlgorithm, Integer>() {
        {
            put(HashAlgorithm.SHA1, 80);
            put(HashAlgorithm.SHA224, 112);
            put(HashAlgorithm.SHA256, 128);
            put(HashAlgorithm.SHA384, 192);
            put(HashAlgorithm.SHA512, 256);
        }
    });

    private final Map<HashAlgorithm, Integer> strengthMap;

    HashAlgorithmStrength(Map<HashAlgorithm, Integer> strength) {
        this.strengthMap = strength;
    }

    public Comparator<HashAlgorithm> getComparator() {
        return Comparator.comparing(this::getStrength);
    }

    public Integer getStrength(HashAlgorithm algorithm) {
        return this.strengthMap.get(algorithm);
    }

    public Map<HashAlgorithm, Integer> getStrengthMap() {
        return strengthMap;
    }
}
