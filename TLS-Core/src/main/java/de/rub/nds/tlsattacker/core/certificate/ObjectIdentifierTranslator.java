/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

public class ObjectIdentifierTranslator {
    private static final BiMap<String, String> oidMap = HashBiMap.create();

    static {
        // Algorithms
        oidMap.put("1.2.840.10045.4.1", "ecdsa-with-SHA1");
        oidMap.put("1.2.840.10045.4.2", "ecdsa-with-Recommended");
        oidMap.put("1.2.840.10045.4.3", "ecdsa-with-SHA2");
        oidMap.put("1.2.840.10045.4.3.1", "ecdsa-with-SHA224");
        oidMap.put("1.2.840.10045.4.3.2", "ecdsa-with-SHA256");
        oidMap.put("1.2.840.10045.4.3.3", "ecdsa-with-SHA384");
        oidMap.put("1.2.840.10045.4.3.4", "ecdsa-with-SHA512");

        oidMap.put("1.2.840.113549.1.1.0", "modules"); // ASN.1 modules?
        oidMap.put("1.2.840.113549.1.1.1", "rsaEncryption");
        oidMap.put("1.2.840.113549.1.1.2", "md2WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.3", "md4withRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.4", "md5WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.5", "sha1-with-rsa-signature");
        oidMap.put("1.2.840.113549.1.1.6", "rsaOAEPEncryptionSet");
        oidMap.put("1.2.840.113549.1.1.7", "id-RSAES-OAEP");
        oidMap.put("1.2.840.113549.1.1.8", "id-mgf1");
        oidMap.put("1.2.840.113549.1.1.9", "id-pSpecified");
        oidMap.put("1.2.840.113549.1.1.10", "rsassa-pss");
        oidMap.put("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.14", "sha224WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.15", "sha512-224WithRSAEncryption");
        oidMap.put("1.2.840.113549.1.1.16", "sha512-256WithRSAEncryption");

        oidMap.put("1.3.14.3.2.1", "rsa");
        oidMap.put("1.3.14.3.2.2", "md4WithRSA");
        oidMap.put("1.3.14.3.2.3", "md5WithRSA");
        oidMap.put("1.3.14.3.2.4", "md4WithRSAEncryption");
        oidMap.put("1.3.14.3.2.6", "desECB");
        oidMap.put("1.3.14.3.2.7", "desCBC");
        oidMap.put("1.3.14.3.2.8", "desOFB");
        oidMap.put("1.3.14.3.2.9", "desCFB");
        oidMap.put("1.3.14.3.2.10", "desMAC");
        oidMap.put("1.3.14.3.2.11", "rsaSignature");
        oidMap.put("1.3.14.3.2.12", "dsa");
        oidMap.put("1.3.14.3.2.13", "dsaWithSHA");
        oidMap.put("1.3.14.3.2.14", "mdc2WithRSASignature");
        oidMap.put("1.3.14.3.2.15", "shaWithRSASignature");
        oidMap.put("1.3.14.3.2.16", "dhWithCommonModulus");
        oidMap.put("1.3.14.3.2.17", "desEDE");
        oidMap.put("1.3.14.3.2.18", "sha");
        oidMap.put("1.3.14.3.2.19", "mdc-2");
        oidMap.put("1.3.14.3.2.20", "dsaCommon");
        oidMap.put("1.3.14.3.2.21", "dsaCommonWithSHA");
        oidMap.put("1.3.14.3.2.22", "rsa-key-transport");
        oidMap.put("1.3.14.3.2.23", "keyed-hash-seal");
        oidMap.put("1.3.14.3.2.24", "md2WithRSASignature");
        oidMap.put("1.3.14.3.2.25", "md5WithRSASignature");
        oidMap.put("1.3.14.3.2.26", "SHA1");
        oidMap.put("1.3.14.3.2.27", "dsaWithSHA1");
        oidMap.put("1.3.14.3.2.28", "dsaWithCommonSHA1");
        oidMap.put("1.3.14.3.2.29", "sha1WithRSAEncryption");

        // Distinguished Name, short form
        oidMap.put("2.5.4.3", "CN");
        oidMap.put("2.5.4.4", "SN");
        oidMap.put("2.5.4.5", "Serial Number");
        oidMap.put("2.5.4.6", "C");
        oidMap.put("2.5.4.7", "L");
        oidMap.put("2.5.4.8", "S");
        oidMap.put("2.5.4.10", "O");
        oidMap.put("2.5.4.11", "OU");
        oidMap.put("2.5.4.12", "Title");
        oidMap.put("2.5.4.42", "GN");
        oidMap.put("2.5.4.43", "Initials");
        oidMap.put("2.5.4.44", "Generation Qualifier");
        oidMap.put("2.5.4.65", "Pseudonym");
    }

    public static String translate(String input) {
        String translated;
        // Forward check
        translated = oidMap.get(input);

        // Reverse check
        if (translated == null) {
            translated = oidMap.inverse().get(input);
        }

        // Return input if not found
        if (translated == null) {
            translated = input;
        }
        return translated;
    }
}
