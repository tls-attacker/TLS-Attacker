/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
