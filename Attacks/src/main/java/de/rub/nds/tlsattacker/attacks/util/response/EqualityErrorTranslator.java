/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.util.response;

/**
 *
 *
 */
public class EqualityErrorTranslator {

    /**
     *
     * @param  error
     * @param  fingerprint1
     * @param  fingerprint2
     * @return
     */
    public static String translation(EqualityError error, ResponseFingerprint fingerprint1,
        ResponseFingerprint fingerprint2) {
        StringBuilder builder = new StringBuilder();
        switch (error) {
            case MESSAGE_CLASS:
                builder.append("The server responds with different protocol messages.");
                break;
            case MESSAGE_COUNT:
                builder.append("The server responds with a different number of protocol messages.");
                break;
            case NONE:
                builder.append(
                    "The server shows no behaviour difference on the protocol / socket layer. The Server seems to be fine.");
                break;
            case RECORD_CLASS:
                builder.append(
                    "The server sometimes responds with something which cannot be interpreted as TLS but sometimes he does.");
                break;
            case RECORD_CONTENT_TYPE:
                builder.append("The server responds with records which differentiate on the record content type.");
                break;
            case RECORD_COUNT:
                builder.append("The server responds with different amounts of records.");
                break;
            case RECORD_LENGTH:
                builder.append("The server seems to respond with records of different lengths.");
                break;
            case RECORD_VERSION:
                builder.append("The server seems to respond with records which have different protocol versions.");
                break;
            case SOCKET_STATE:
                builder.append("The server seems to occasionally move the TCP socket in different states.");
                break;
            case MESSAGE_CONTENT:
                builder.append("The server responded with different message contents");
                break;
            case RECORD_CONTENT:
                builder.append("The server responded with different record contents.");
                break;
            default:
                builder.append(error.toString());
        }
        return builder.toString();
    }

    private EqualityErrorTranslator() {
    }
}
