/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
    SOCKET_STATE,
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
    MESSAGE_CONTENT,
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
    RECORD_VERSION,
    /**
     *
     */
    ALERT_MESSAGE_CONTENT, // TODO TO BE REMOVED
    ALERT_RECORD_CONTENT, // TODO TO BE REMOVED
    RECORD_CONTENT;

}
