/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.check;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public enum CheckType {
    CERTIFICATE_EXPIRED,
    CERTIFICATE_NOT_VALID_YET,
    CERTIFICATE_REVOKED,
    CERTIFICATE_WEAK_HASH_FUNCTION,
    CERTIFICATE_WEAK_SIGN_ALGORITHM,
    CERTIFICATE_SENT_BY_SERVER,
    CIPHERSUITE_ANON,
    CIPHERSUITE_CBC,
    CIPHERSUITE_EXPORT,
    CIPHERSUITE_NULL,
    CIPHERSUITE_RC4,
    CIPHERSUITEORDER_ENFORCED,
    PROTOCOLVERSION_SSL2,
    PROTOCOLVERSION_SSL3,
}
