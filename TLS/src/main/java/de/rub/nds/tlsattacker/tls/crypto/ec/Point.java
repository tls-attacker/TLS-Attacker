/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto.ec;

import java.math.BigInteger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class Point {

    protected BigInteger x;
    protected BigInteger y;
    private boolean infinity;

    public Point() {
    }

    public Point(boolean infinity) {
	this.infinity = infinity;
    }

    public Point(BigInteger x, BigInteger y) {
	this.x = x;
	this.y = y;
    }

    public Point(String x, String y) {
	this.x = new BigInteger(x);
	this.y = new BigInteger(y);
    }

    public BigInteger getX() {
	return x;
    }

    public void setX(BigInteger x) {
	this.x = x;
    }

    public BigInteger getY() {
	return y;
    }

    public void setY(BigInteger y) {
	this.y = y;
    }

    public boolean isInfinity() {
	return infinity;
    }

    public void setInfinity(boolean infinity) {
	this.infinity = infinity;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (getClass() != obj.getClass()) {
	    return false;
	}
	Point p = (Point) obj;
	if (p.isInfinity() == true && this.isInfinity() == true) {
	    return true;
	}
	if (p.getX().equals(this.getX()) && p.getY().equals(this.getY())) {
	    return true;
	}
	return false;
    }

    @Override
    public int hashCode() {
	if (isInfinity()) {
	    return 0;
	} else {
	    return this.getX().mod(new BigInteger(Integer.toString(Integer.MAX_VALUE))).intValue();
	}
    }

    @Override
    public String toString() {
	return "x: " + x + "\ny: " + y;
    }
}
