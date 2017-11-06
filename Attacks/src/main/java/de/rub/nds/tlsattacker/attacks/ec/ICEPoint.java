/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;


public class ICEPoint extends Point {

    private int order;

    public ICEPoint() {

    }

    public ICEPoint(int order, BigInteger x, BigInteger y) {
        super(x, y);
        this.order = order;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Point order: ").append(order).append("\nX: ").append(x).append("\nY: ").append(y);
        return sb.toString();
    }

}
