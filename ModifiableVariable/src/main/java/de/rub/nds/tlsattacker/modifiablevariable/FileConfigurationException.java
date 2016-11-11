/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class FileConfigurationException extends RuntimeException {

    public FileConfigurationException() {

    }

    public FileConfigurationException(Exception ex) {
        super(ex);
    }

    public FileConfigurationException(String message, Exception ex) {
        super(message, ex);
    }
}
