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
}
