/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

/**
 * @author juraj
 */
public class ExtensionByteLength {

    /**
     * extensions byte length
     */
    public static final int EXTENSIONS_LENGTH = 2;

    /**
     * extension type
     */
    public static final int TYPE = 2;

    /**
     * EC point formats length field of the ec point format extension message
     */
    public static final int EC_POINT_FORMATS_LENGTH = 1;

    /**
     * Supported Elliptic Curves length field of the elliptic curve extension
     * message
     */
    public static final int SUPPORTED_ELLIPTIC_CURVES_LENGTH = 2;
    /**
     * Heartbeat mode length in the heartbeat extension message
     */
    public static final int HEARTBEAT_MODE_LENGTH = 1;
    /**
     * MaxFragment length field in the MaxFragmentExtension message
     */
    public static final int MAX_FRAGMENT_EXTENSION_LENGTH = 1;
    /**
     * ServernameType length in the ServerNameIndicationExtension
     */
    public static final int SERVER_NAME_TYPE = 1;
    /**
     * ServerName length in the ServerNameIndicationExtension
     */
    public static final int SERVER_NAME_LENGTH = 2;
    /**
     * ServerNameListLength in the ServerNameIndicationExtension
     */
    public static final int SERVER_NAME_LIST_LENGTH = 2;
    /**
     * KeyShareType length in the KeySahreExtension
     */
    public static final int KEY_SHARE_TYPE = 2;
    /**
     * KeyShare length in the KeySahreExtension
     */
    public static final int KEY_SAHRE_LENGTH = 2;
    /**
     * KeyShareListLength in the KeySahreExtension
     */
    public static final int KEY_SHARE_LIST_LENGTH = 2;
    /**
     * Length of the Signature and HashAlgorithm Length field of the
     * SignatureAndHashAlgorithms Extension
     */
    public static final int SIGNATURE_AND_HASH_ALGORITHMS_LENGTH = 2;
    /**
     * Supported Protocol Versions length field of the
     * SupportedVersionsExtension message
     */
    public static final int SUPPORTED_PROTOCOL_VERSIONS_LENGTH = 1;
}
