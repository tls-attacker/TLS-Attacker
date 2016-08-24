/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public enum ModificationType {
    ADD_MESSAGE,
    DUPLICATE_MESSAGE,
    REMOVE_MESSAGE,
    MODIFY_FIELD,
    ADD_RECORD,
    CHANGE_SERVER_CERT,
    CHANGE_CLIENT_CERT,
}
