/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public class HandshakeByteLength {

    /** Type length */
    public static final int TYPE_LENGTH = 1;

    /** Length length */
    public static final int HANDSHAKE_MESSAGE_LENGTH_FIELD_LENGTH = 3;

    /** certificate length field */
    public static final int CERTIFICATE_LENGTH = 3;

    /** certificate request context length field */
    public static final int CERTIFICATE_REQUEST_CONTEXT_LENGTH = 1;

    /** version field length */
    public static final int VERSION = 2;

    /** extension length field length */
    public static final int EXTENSION_LENGTH = 2;

    /** certificates length field (certificate array can include several certificates) */
    public static final int CERTIFICATES_LENGTH = 3;

    /** cipher suite length field length */
    public static final int CIPHER_SUITES_LENGTH = 2;

    /** cipher suite byte length */
    public static final int CIPHER_SUITE = 2;

    /** compression length */
    public static final int COMPRESSION = 1;

    /** compression length field length */
    public static final int COMPRESSION_LENGTH = 1;

    /** message type length */
    public static final int MESSAGE_TYPE = 1;

    /** length of the length field included in this message type */
    public static final int MESSAGE_LENGTH_FIELD = 3;

    /** random length */
    public static final int RANDOM = 32;

    /** length of the session id length field indicating the session id length */
    public static final int SESSION_ID_LENGTH = 1;

    /** length of the dtls cookie length field indicating the dtls cookie length */
    public static final int DTLS_COOKIE_LENGTH = 1;

    /** unix time byte length */
    public static final int UNIX_TIME = 4;

    /** Premaster Secret */
    public static final int PREMASTER_SECRET = 48;

    /** Length of the length field for the encrypted Premaster Secret */
    public static final int ENCRYPTED_PREMASTER_SECRET_LENGTH = 2;

    /** Master Secret */
    public static final int MASTER_SECRET = 48;

    /** Verify data from the finished message */
    public static final int VERIFY_DATA = 12;

    /** Length of the signature length field */
    public static final int SIGNATURE_LENGTH = 2;

    /** DH modulus length */
    public static final int DH_MODULUS_LENGTH = 2;

    /** DH generator length */
    public static final int DH_GENERATOR_LENGTH = 2;

    /** DH public key length */
    public static final int DH_PUBLICKEY_LENGTH = 2;

    /** DHE param length */
    public static final int DHE_PARAM_LENGTH = 2;

    /** ECDH param length */
    public static final int ECDH_PARAM_LENGTH = 1;

    /** ECDHE param length */
    public static final int ECDHE_PARAM_LENGTH = 1;

    /** Certificate Types Count in CertRequest */
    public static final int CERTIFICATES_TYPES_COUNT = 1;

    /** Length of the signature hash algorithms length field */
    public static final int SIGNATURE_HASH_ALGORITHMS_LENGTH = 2;

    /** Length of the signature algorithm field */
    public static final int SIGNATURE = 1;

    /** Length of the hash algorithm field */
    public static final int HASH = 1;

    /** Length of the signature hash algorithms field in the certificateVerify message */
    public static final int SIGNATURE_HASH_ALGORITHM = 2;

    /** Length of the distinguished names length field */
    public static final int DISTINGUISHED_NAMES_LENGTH = 2;

    /** Length of an elliptic curve field */
    public static final int ELLIPTIC_CURVE = 1;

    /** Length of a named group constant */
    public static final int NAMED_GROUP = 2;

    /** Length of the cookie field in DTLS ClientHello and ClientHelloVerify messages. */
    public static final int DTLS_HANDSHAKE_COOKIE_LENGTH = 1;

    /** Length of the Message Sequence field */
    public static final int DTLS_MESSAGE_SEQUENCE = 2;

    /** Fragment Offset length */
    public static final int DTLS_FRAGMENT_OFFSET = 3;

    /** Fragment length */
    public static final int DTLS_FRAGMENT_LENGTH = 3;

    /** Length of PSK_Identity */
    public static final int PSK_IDENTITY_LENGTH = 2;

    public static final int PSK_LENGTH = 2;

    public static final int PSK_ZERO = 0;

    public static final int SRP_MODULUS_LENGTH = 2;

    public static final int SRP_SALT_LENGTH = 1;

    public static final int SRP_GENERATOR_LENGTH = 2;

    public static final int SRP_PUBLICKEY_LENGTH = 2;

    /** New Session Ticket */
    public static final int NEWSESSIONTICKET_TICKET_LENGTH = 2;

    public static final int NEWSESSIONTICKET_LIFETIMEHINT_LENGTH = 4;

    public static final int ENCRYPTED_STATE_LENGTH = 2;

    public static final int TICKET_AGE_ADD_LENGTH = 4;

    public static final int TICKET_NONCE_LENGTH = 1;

    /** length of the ClientAuthenticationType in the TLS byte arrays */
    public static final int CLIENT_AUTHENTICATION_TYPE = 1;

    /** Length of the Supplemental Data Field */
    public static final int SUPPLEMENTAL_DATA_LENGTH = 3;

    /** Length of the Supplemental Data Entry Type */
    public static final int SUPPLEMENTAL_DATA_ENTRY_TYPE_LENGTH = 2;

    /** Length of the Supplemental Data Entry */
    public static final int SUPPLEMENTAL_DATA_ENTRY_LENGTH = 2;

    /** Length of the salt in PWD */
    public static final int PWD_SALT_LENGTH = 1;

    /** Length of the element in PWD */
    public static final int PWD_ELEMENT_LENGTH = 1;

    /** Length of the scalar in PWD */
    public static final int PWD_SCALAR_LENGTH = 1;

    /** certificate status type length field */
    public static final int CERTIFICATE_STATUS_TYPE_LENGTH = 1;

    /** certificate status response length field */
    public static final int CERTIFICATE_STATUS_RESPONSE_LENGTH = 3;

    /** RSA modulus length */
    public static final int RSA_MODULUS_LENGTH = 2;

    /** RSA public key length */
    public static final int RSA_PUBLICKEY_LENGTH = 2;

    /** KeyUpdate Message Length */
    public static final int KEY_UPDATE_LENGTH = 1;

    /** RequestConnectionId number of CIDs length */
    public static final int REQUEST_CONNECTION_ID_NUMBER_CIDS_LENGTH = 1;

    /** NewConnectionId length of the number of CIDs */
    public static final int NEW_CONNECTION_ID_CIDS_LENGTH = 2;

    /** NewConnectionId usage length */
    public static final int NEW_CONNECTION_ID_USAGE_LENGTH = 1;

    /** ConnectionId length field length */
    public static final int CONNECTION_ID_LENGTH = 1;

    private HandshakeByteLength() {}
}
