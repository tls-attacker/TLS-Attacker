/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.util.response;

/**
 *
 *
 */
public enum EqualityError {

    /**
     *
     */
    NONE,
    /**
     *
     */
    SOCKET_EXCEPTION,
    /**
     *
     */
    SOCKET_STATE,
    /**
     *
     */
    ALERT_COUNT,
    /**
     *
     */
    MESSAGE_COUNT,
    /**
     *
     */
    RECORD_COUNT,
    /**
     *
     */
    RECORD_CLASS,
    /**
     *
     */
    MESSAGE_CLASS,
    /**
     *
     */
    ALERT_RECORD_CONTENT,
    /**
     *
     */
    ALERT_MESSAGE_CONTENT,
    /**
     *
     */
    ENCRYPTED_ALERT,
    /**
     *
     */
    RECORD_CONTENT_TYPE,
    /**
     *
     */
    RECORD_LENGTH,
    /**
     *
     */
    RECORD_VERSION;

}
