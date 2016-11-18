/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

/**
 * An enum for every modification.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public enum ModificationType {

    /**
     * If a Message was added
     */
    ADD_MESSAGE,

    /**
     * If a Message was duplicated
     */
    DUPLICATE_MESSAGE,

    /**
     * If a Message was removed
     */
    REMOVE_MESSAGE,

    /**
     * If a field was modified
     */
    MODIFY_FIELD,

    /**
     * If a record was added
     */
    ADD_RECORD,

    /**
     * If the Server certificate was changed
     */
    CHANGE_SERVER_CERT,

    /**
     * If the Client certificate was changed
     */
    CHANGE_CLIENT_CERT,

    /**
     * If a Send and ReceiveAction was added
     */
    ADD_MESSAGE_FLIGHT,

    /**
     * If a ToggleEncryptionAction was added
     */
    TOGGLE_ENCRYPTION,

    /**
     * If a ChangeCiphersuiteAction was added
     */
    ADD_CHANGE_CIPHERSUITE_ACTION,

    /**
     * If a ChangeClientCertificate action was added
     */
    ADD_CHANGE_CLIENT_CERTIFICATE_ACTION,

    /**
     * If a ChangeClientRandomAction was added
     */
    ADD_CHANGE_CLIENT_RANDOM_ACTION,

    /**
     * If a ChangeCompressionAction was added
     */
    ADD_CHANGE_COMPRESSION_ACTION,

    /**
     * If a ChangeMasterSecretAction was added
     */
    ADD_CHANGE_MASTER_SECRET_ACTION,

    /**
     * If a ChangePremasterSecretAction was added
     */
    ADD_CHANGE_PREMASTER_SECRET_ACTION,

    /**
     * If a ChangeProtocolVersionAction was added
     */
    ADD_CHANGE_PROTOCOL_VERSION_ACTION,

    /**
     * If a ChangeServerCertificateAction was added
     */
    ADD_CHANGE_SERVER_CERTIFICATE_ACTION,

    /**
     * If a ChangeServerRandomAction was added
     */
    ADD_CHANGE_SERVER_RANDOM_ACTION,

    /**
     * If an Extension was added
     */
    ADD_EXTENSION
}
