/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

public class CurveNameRetriever {

    public static NamedGroup getNamedCuveFromECCurve(ECCurve unknownCurve) {
        for (NamedGroup group : NamedGroup.values()) {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(group.name());
            if (parameterSpec.getCurve().equals(unknownCurve)) {
                return group;
            }
        }
        return null;
    }

    private CurveNameRetriever() {
    }
}
