/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.exceptions;

/**
 * Exception thrown when an undefined Mutator is configured
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IllegalMutatorException extends Exception {

    public IllegalMutatorException(String string) {
	super(string);
    }

}
