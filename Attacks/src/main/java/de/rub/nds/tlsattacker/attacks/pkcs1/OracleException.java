package de.rub.nds.tlsattacker.attacks.pkcs1;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class OracleException extends RuntimeException {

    public OracleException() {

    }

    public OracleException(String message) {
	super(message);
    }

    public OracleException(String message, Throwable t) {
	super(message, t);
    }

}
