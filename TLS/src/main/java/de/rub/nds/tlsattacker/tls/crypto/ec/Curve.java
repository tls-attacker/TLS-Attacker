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
