package de.rub.nds.tlsattacker.tls.crypto.ec;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class DivisionException extends Exception {

    private int round;

    public DivisionException(String message) {
	super(message);
    }

    public DivisionException(String message, int i) {
	super(message + " Error happend in round " + i);
	round = i;
    }

    public int getRound() {
	return round;
    }
}
