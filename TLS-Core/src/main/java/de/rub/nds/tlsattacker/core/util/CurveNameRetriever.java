/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

public class CurveNameRetriever {

    public static NamedGroup getNamedCurveFromECCurve(ECCurve unknownCurve) {
        for (NamedGroup group : NamedGroup.values()) {
            ECNamedCurveParameterSpec parameterSpec =
                    ECNamedCurveTable.getParameterSpec(group.name());
            if (parameterSpec.getCurve().equals(unknownCurve)) {
                return group;
            }
        }
        return null;
    }

    private CurveNameRetriever() {}
}
