/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExtensionParserFactory {

    public static ExtensionParser getExtensionParser(int startPosition, byte[] array) {
        // Try to read the type, else just return unknown
        ExtensionType type = ExtensionType.UNKNOWN;
        if (array.length - startPosition >= 2) {
            byte[] byteType = new byte[2];
            byteType[0] = array[startPosition];
            byteType[1] = array[startPosition + 1];
            type = ExtensionType.getExtensionType(byteType);
        }
        switch (type) {
            case CLIENT_CERTIFICATE_URL:
                break;
            case EC_POINT_FORMATS:
                break;
            case ELLIPTIC_CURVES:
                break;
            case HEARTBEAT:
                break;
            case MAX_FRAGMENT_LENGTH:
                break;
            case SERVER_NAME_INDICATION:
                break;
            case SIGNATURE_AND_HASH_ALGORITHMS:
                break;
            case STATUS_REQUEST:
                break;
            case TRUNCATED_HMAC:
                break;
            case TRUSTED_CA_KEYS:
                break;
            case UNKNOWN:
                return new UnknownExtensionParser(startPosition, array);
        }
        return new UnknownExtensionParser(startPosition, array);
    }
}
