package de.rub.nds.tlsattacker.tls.crypto.ec;

import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ECComputer {

    static Logger LOGGER = LogManager.getLogger(ECComputer.class);
    private static BigInteger TWO = BigInteger.valueOf(2);
    private static BigInteger THREE = BigInteger.valueOf(3);
    /**
     * curve with its parameters
     */
    private Curve curve;
    /**
     * secret we use to multiply a given point
     */
    private BigInteger secret;

    public ECComputer() {

    }

    public ECComputer(Curve c, BigInteger s) {
	this.curve = c;
	this.secret = s;
    }

    /**
     * Doubles point, does not check for infinity
     * 
     * @param p
     * @return
     * @throws DivisionException
     *             exception occurs if y coordinate is zero
     */
    public Point dbl(Point p) throws DivisionException {

	BigInteger x = p.getX();
	BigInteger y = p.getY();

	if (y.equals(BigInteger.ZERO)) {
	    throw new DivisionException("y was equal to zero");
	}

	BigInteger l1 = ((THREE.multiply(x.pow(2))).add(curve.getA()));
	BigInteger l2 = TWO.multiply(y).modInverse(curve.getP());
	BigInteger l = l1.multiply(l2).mod(curve.getP());

	BigInteger xr = l.pow(2).subtract(TWO.multiply(x)).mod(curve.getP());
	BigInteger yr = l.multiply(x.subtract(xr)).subtract(y).mod(curve.getP());
	Point ret = new Point(xr, yr);
	return ret;
    }

    /**
     * Doubles point, checks for infinity if checkInfinity set
     * 
     * @param p
     * @param checkInfinity
     * @return
     * @throws DivisionException
     */
    public Point dbl(Point p, boolean checkInfinity) throws DivisionException {
	if (checkInfinity) {
	    if (p.isInfinity()) {
		return p;
	    }
	    if (p.getY().signum() == 0) {
		return new Point(true);
	    }
	}
	return dbl(p);
    }

    /**
     * Provides point addition, without infinity check
     * 
     * @param p
     * @param q
     * @return
     * @throws DivisionException
     *             exception thrown if xq=xp, since then we divide with zero
     */
    public Point add(Point p, Point q) throws DivisionException {
	BigInteger xp = p.getX();
	BigInteger yp = p.getY();
	BigInteger xq = q.getX();
	BigInteger yq = q.getY();

	if (xq.subtract(xp).mod(curve.getP()).equals(BigInteger.ZERO)) {
	    throw new DivisionException("xq was equal to xp (mod p)");
	}

	BigInteger l = ((yq.subtract(yp)).multiply((xq.subtract(xp)).modInverse(curve.getP()))).mod(curve.getP());
	BigInteger xr = l.pow(2).subtract(xp).subtract(xq).mod(curve.getP());
	BigInteger yr = (l.multiply(xp.subtract(xr))).subtract(yp).mod(curve.getP());
	Point ret = new Point(xr, yr);
	return ret;
    }

    /**
     * Provides point addition, checks for infinity in case checkInfinity is set
     * 
     * @param p
     * @param q
     * @param checkInfinity
     * @return
     * @throws DivisionException
     */
    public Point add(Point p, Point q, boolean checkInfinity) throws DivisionException {
	if (checkInfinity) {
	    if (p == null || p.isInfinity()) {
		return q;
	    }
	    if (q == null || q.isInfinity()) {
		return p;
	    }

	    if (p.getX().equals(q.getX())) {
		if (p.getY().equals(q.getY())) {
		    return dbl(p, true);
		} else {
		    return new Point(true);
		}
	    }
	}
	return add(p, q);
    }

    /**
     * Simple point multiplication
     * 
     * @param p
     * @param checkInfinity
     * @return
     * @throws DivisionException
     */
    public Point mul(Point p, boolean checkInfinity) throws DivisionException {

	Point r = new Point(p.getX(), p.getY());
	for (int i = 1; i < secret.bitLength(); i++) {
	    try {
		r = dbl(r, checkInfinity);
		if (secret.testBit(secret.bitLength() - 1 - i)) {
		    r = add(r, p, checkInfinity);
		}
	    } catch (DivisionException e) {
		throw new DivisionException(e.getLocalizedMessage(), i);
	    }
	}
	return r;
    }

    /**
     * 
     * @param p
     * @return
     * @throws DivisionException
     */
    public Point mul(Point p) throws DivisionException {
	return mul(p, true);
    }

    public Curve getCurve() {
	return curve;
    }

    public void setCurve(Curve curve) {
	this.curve = curve;
    }

    public BigInteger getSecret() {
	return secret;
    }

    public void setSecret(BigInteger secret) {
	this.secret = secret;
    }
}
