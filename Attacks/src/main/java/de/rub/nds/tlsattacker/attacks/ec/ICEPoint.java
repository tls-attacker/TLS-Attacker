/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;

public class ICEPoint extends Point {

    private final int order;

    public ICEPoint(BigInteger x, BigInteger y, EllipticCurve curve, int order) {
        super(curve.createFieldElement(x), curve.createFieldElement(y));
        this.order = order;
    }

    public int getOrder() {
        return order;
    }
}
