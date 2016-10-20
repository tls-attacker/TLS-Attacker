/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

/**
 * An enum for every modification.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public enum ModificationType {

    /**
     *
     */
    ADD_MESSAGE,

    /**
     *
     */
    DUPLICATE_MESSAGE,

    /**
     *
     */
    REMOVE_MESSAGE,

    /**
     *
     */
    MODIFY_FIELD,

    /**
     *
     */
    ADD_RECORD,

    /**
     *
     */
    CHANGE_SERVER_CERT,

    /**
     *
     */
    CHANGE_CLIENT_CERT,

    /**
     *
     */
    ADD_MESSAGE_FLIGHT,

    /**
     *
     */
    TOGGLE_ENCRYPTION,

    /**
     *
     */
    ADD_CHANGE_CIPHERSUITE_ACTION,

    /**
     *
     */
    ADD_CHANGE_CLIENT_CERTIFICATE_ACTION,

    /**
     *
     */
    ADD_CHANGE_CLIENT_RANDOM_ACTION,

    /**
     *
     */
    ADD_CHANGE_COMPRESSION_ACTION,

    /**
     *
     */
    ADD_CHANGE_MASTER_SECRET_ACTION,

    /**
     *
     */
    ADD_CHANGE_PREMASTER_SECRET_ACTION,

    /**
     *
     */
    ADD_CHANGE_PROTOCOL_VERSION_ACTION,

    /**
     *
     */
    ADD_CHANGE_SERVER_CERTIFICATE_ACTION,

    /**
     *
     */
    ADD_CHANGE_SERVER_RANDOM_ACTION,

    /**
     *
     */
    ADD_EXTENSION
}
