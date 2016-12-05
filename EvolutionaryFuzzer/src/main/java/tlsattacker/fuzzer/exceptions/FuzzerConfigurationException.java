/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.exceptions;

/**
 * Exception thrown if the Fuzzer is not correctly configured.
 * @author ic0ns
 */
public class FuzzerConfigurationException extends Exception{

    public FuzzerConfigurationException(String message) {
        super(message);
    }
    
}
