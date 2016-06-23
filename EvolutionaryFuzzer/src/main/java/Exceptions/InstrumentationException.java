/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Exceptions;

/**
 * This Exception should be thrown if a Bug in the Instrumentation is suspected!
 * @author Robert Merget - robert.merget@rub.de
 */
public class InstrumentationException extends RuntimeException
{

    public InstrumentationException(String message)
    {
        super(message);
    }

    
}
