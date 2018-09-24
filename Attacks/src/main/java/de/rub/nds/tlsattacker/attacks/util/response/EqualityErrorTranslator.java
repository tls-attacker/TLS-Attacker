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
public class EqualityErrorTranslator {

    /**
     *
     * @param error
     * @param fingerprint1
     * @param fingerprint2
     * @return
     */
    public static String translation(EqualityError error, ResponseFingerprint fingerprint1,
            ResponseFingerprint fingerprint2) {
        StringBuilder builder = new StringBuilder();
        switch (error) {
            case ALERT_COUNT:
                builder.append("The server seems to respond with a different number of alerts.");
                break;
            case ALERT_MESSAGE_CONTENT:
                builder.append("The server seems to answer with differnt alerts.");
                break;
            case ALERT_RECORD_CONTENT:
                builder.append("The server seems to respond with different record conntents.");
                break;
            case ENCRYPTED_ALERT:
                builder.append("The server seems to encrypt some but not all of its alert records.");
                break;
            case MESSAGE_CLASS:
                builder.append("The server responds with different protocol messages.");
                break;
            case MESSAGE_COUNT:
                builder.append("The server responds with a differnt number of protocol messages.");
                break;
            case NONE:
                builder.append("The server shows no behaviour difference on the protocol / socket layer. The Server seems to be fine.");
                break;
            case RECORD_CLASS:
                builder.append("The server sometimes responds with something which cannot be interpreted as TLS but sometimes he does.");
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
            case SOCKET_EXCEPTION:
                builder.append("The server seems to ocassionally respond with a socket exception.");
                break;
            case SOCKET_STATE:
                builder.append("The server seems to ocassionally move the TCP socket in different states.");
                break;
            default:
                builder.append(error.toString());
        }
        return builder.toString();
    }

    private EqualityErrorTranslator() {
    }
}
