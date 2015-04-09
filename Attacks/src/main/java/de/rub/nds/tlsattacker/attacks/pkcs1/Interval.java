package de.rub.nds.tlsattacker.attacks.pkcs1;

import java.math.BigInteger;

/**
 * M interval as mentioned in the Bleichenbacher paper.
 * 
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * 
 *          May 24, 2012
 */
public class Interval {

    public BigInteger lower;
    public BigInteger upper;

    public Interval(BigInteger a, BigInteger b) {
	this.lower = a;
	this.upper = b;
	if (a.compareTo(b) > 0) {
	    throw new RuntimeException("something went wrong, a cannot be greater than b");
	}
    }
}
