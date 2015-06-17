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
import java.util.Objects;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class Curve {

    private String name;
    private BigInteger p;
    private BigInteger a;
    private BigInteger b;
    private int keyBits;

    public Curve() {

    }

    public Curve(String name, BigInteger p, BigInteger a, BigInteger b, int keyBits) {
	this.name = name;
	this.p = p;
	this.a = a;
	this.b = b;
	this.keyBits = keyBits;
    }

    public String getName() {
	return name;
    }

    public void setName(String value) {
	name = value;
    }

    public BigInteger getP() {
	return p;
    }

    public void setP(BigInteger p) {
	this.p = p;
    }

    public BigInteger getA() {
	return a;
    }

    public void setA(BigInteger a) {
	this.a = a;
    }

    public BigInteger getB() {
	return b;
    }

    public void setB(BigInteger b) {
	this.b = b;
    }

    public int getKeyBits() {
	return keyBits;
    }

    public void setKeyBits(int keyBits) {
	this.keyBits = keyBits;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (getClass() != obj.getClass()) {
	    return false;
	}
	final Curve other = (Curve) obj;
	if ((this.name == null) ? (other.name != null) : !this.name.equals(other.name)) {
	    return false;
	}

	return true;
    }

    @Override
    public int hashCode() {
	int hash = 7;
	hash = 67 * hash + Objects.hashCode(this.name);
	hash = 67 * hash + Objects.hashCode(this.p);
	hash = 67 * hash + Objects.hashCode(this.a);
	hash = 67 * hash + Objects.hashCode(this.b);
	return hash;
    }
}
