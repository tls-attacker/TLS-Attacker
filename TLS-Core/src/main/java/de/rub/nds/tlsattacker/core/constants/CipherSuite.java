/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.UnknownCipherSuiteException;

public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(0x0000, CipherType.STREAM, KeyExchangeAlgorithm.NULL,
            CipherAlgorithm.NULL, HashAlgorithm.NONE, false, false),
    TLS_RSA_WITH_NULL_MD5(0x0001, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.NULL, HashAlgorithm.MD5, false, false),
    TLS_RSA_WITH_NULL_SHA(0x0002, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_RSA_EXPORT_WITH_RC4_40_MD5(0x0003, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.RC4_40, HashAlgorithm.MD5, true, false),
    TLS_RSA_WITH_RC4_128_MD5(0x0004, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.MD5, false, false),
    TLS_RSA_WITH_RC4_128_SHA(0x0005, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(0x0006, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.RC2_40, HashAlgorithm.MD5, false, false),
    TLS_RSA_WITH_IDEA_CBC_SHA(0x0007, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.IDEA_128, HashAlgorithm.SHA1, false, false),
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0008, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_RSA_WITH_DES_CBC_SHA(0x0009, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000A, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(0x000B, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DH_DSS_WITH_DES_CBC_SHA(0x000C, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x000D, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(0x000E, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DH_RSA_WITH_DES_CBC_SHA(0x000F, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x0010, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(0x0011, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DHE_DSS_WITH_DES_CBC_SHA(0x0012, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x0013, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(0x0014, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DHE_RSA_WITH_DES_CBC_SHA(0x0015, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(0x0017, CipherType.STREAM, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.RC4_40, HashAlgorithm.MD5, true, false),
    TLS_DH_anon_WITH_RC4_128_MD5(0x0018, CipherType.STREAM, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.RC4_128, HashAlgorithm.MD5, false, false),
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(0x0019, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DH_anon_WITH_DES_CBC_SHA(0x001A, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(0x001B, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    SSL_FORTEZZA_KEA_WITH_NULL_SHA(0x001C, CipherType.STREAM, KeyExchangeAlgorithm.FORTEZZA_KEA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA(0x001D, CipherType.BLOCK, KeyExchangeAlgorithm.FORTEZZA_KEA,
            CipherAlgorithm.FORTEZZA_CBC, HashAlgorithm.SHA1, false, false),
    TLS_KRB5_WITH_DES_CBC_SHA(0x001E, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    // TODO this cipher suite clashes with
    // SSL_FORTEZZA_KEA_WITH_RC4_128_SHA(0x001E)
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA(0x001F, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_KRB5_WITH_RC4_128_SHA(0x0020, CipherType.STREAM, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_KRB5_WITH_IDEA_CBC_SHA(0x0021, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.IDEA_128, HashAlgorithm.SHA1, false, false),
    TLS_KRB5_WITH_DES_CBC_MD5(0x0022, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_CBC, HashAlgorithm.MD5, false, false),
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5(0x0023, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.MD5, false, false),
    TLS_KRB5_WITH_RC4_128_MD5(0x0024, CipherType.STREAM, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC4_128, HashAlgorithm.MD5, false, false),
    TLS_KRB5_WITH_IDEA_CBC_MD5(0x0025, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.IDEA_128, HashAlgorithm.MD5, false, false),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA(0x0026, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, true, false),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA(0x0027, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC2_40, HashAlgorithm.SHA1, true, false),
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA(0x0028, CipherType.STREAM, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC4_40, HashAlgorithm.SHA1, true, false),
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5(0x0029, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.DES_CBC, HashAlgorithm.MD5, true, false),
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5(0x002A, CipherType.BLOCK, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC2_40, HashAlgorithm.MD5, true, false),
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5(0x002B, CipherType.STREAM, KeyExchangeAlgorithm.KRB5,
            CipherAlgorithm.RC4_40, HashAlgorithm.MD5, true, false),
    TLS_PSK_WITH_NULL_SHA(0x002C, CipherType.STREAM, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_DHE_PSK_WITH_NULL_SHA(0x002D, CipherType.STREAM, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_RSA_PSK_WITH_NULL_SHA(0x002E, CipherType.STREAM, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x002F, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x0030, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x0031, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_AES_128_CBC_SHA(0x0034, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x0035, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x0036, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x0037, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_AES_256_CBC_SHA(0x003A, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_NULL_SHA256(0x003B, CipherType.STREAM, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x003E, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x003F, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0042, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0043, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0044, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(0x0046, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_NULL_SHA(0x0047, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0x0048, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_DES_CBC_SHA(0x0049, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0x004A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_NULL_SHA(0x004B, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECNRA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_RC4_128_SHA(0x004C, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECNRA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_DES_CBC_SHA(0x004D, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECNRA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA(0x004E, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECNRA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_NULL_SHA(0x004F, CipherType.STREAM, KeyExchangeAlgorithm.ECMQV_ECDSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_RC4_128_SHA(0x0050, CipherType.STREAM, KeyExchangeAlgorithm.ECMQV_ECDSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA(0x0051, CipherType.BLOCK, KeyExchangeAlgorithm.ECMQV_ECDSA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA(0x0052, CipherType.BLOCK, KeyExchangeAlgorithm.ECMQV_ECDSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_NULL_SHA(0x0053, CipherType.STREAM, KeyExchangeAlgorithm.ECMQV_ECNRA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_RC4_128_SHA(0x0054, CipherType.STREAM, KeyExchangeAlgorithm.ECMQV_ECNRA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA(0x0055, CipherType.BLOCK, KeyExchangeAlgorithm.ECMQV_ECNRA,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA(0x0056, CipherType.BLOCK, KeyExchangeAlgorithm.ECMQV_ECNRA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_anon_WITH_NULL_SHA(0x0057, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_anon_WITH_RC4_128_SHA(0x0058, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_anon_WITH_DES_CBC_SHA(0x0059, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0x005A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA(0x005B, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.DES40_CBC, HashAlgorithm.SHA1, true, false),
    UNOFFICIAL_TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA(0x005C, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.RC4_40, HashAlgorithm.SHA1, true, false),
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5(0x0060, CipherType.STREAM, KeyExchangeAlgorithm.RSA_EXPORT,
            CipherAlgorithm.RC4_56, HashAlgorithm.MD5, true, false),
    TLS_RSA_EXPORT1024_WITH_RC2_56_MD5(0x0061, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_EXPORT,
            CipherAlgorithm.RC2_56, HashAlgorithm.MD5, true, false),
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA(0x0062, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_EXPORT,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, true, false),
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA(0x0063, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.DES_CBC, HashAlgorithm.SHA1, true, false),
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA(0x0064, CipherType.STREAM, KeyExchangeAlgorithm.RSA_EXPORT,
            CipherAlgorithm.RC4_56, HashAlgorithm.SHA1, true, false),
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA(0x0065, CipherType.STREAM, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.RC4_56, HashAlgorithm.SHA1, true, false),
    TLS_DHE_DSS_WITH_RC4_128_SHA(0x0066, CipherType.STREAM, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x0068, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x0069, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_AES_128_CBC_SHA256(0x006C, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_AES_256_CBC_SHA256(0x006D, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_GOSTR341094_WITH_28147_CNT_IMIT(0x0080, CipherType.BLOCK, KeyExchangeAlgorithm.VKO_GOST01,
            CipherAlgorithm.GOST_28147_CNT_IMIT, HashAlgorithm.GOST_R3411_94, false, false),
    TLS_GOSTR341001_WITH_28147_CNT_IMIT(0x0081, CipherType.BLOCK, KeyExchangeAlgorithm.VKO_GOST12,
            CipherAlgorithm.GOST_28147_CNT_IMIT, HashAlgorithm.GOST_R3411_94, false, false),
    TLS_GOSTR341094_WITH_NULL_GOSTR3411(0x0082, CipherType.STREAM, KeyExchangeAlgorithm.VKO_GOST01,
            CipherAlgorithm.NULL, HashAlgorithm.GOST_R3411_94, false, false),
    TLS_GOSTR341001_WITH_NULL_GOSTR3411(0x0083, CipherType.STREAM, KeyExchangeAlgorithm.VKO_GOST12,
            CipherAlgorithm.NULL, HashAlgorithm.GOST_R3411_94, false, false),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0085, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0086, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0087, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(0x0089, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_PSK_WITH_RC4_128_SHA(0x008A, CipherType.STREAM, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x008B, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_PSK_WITH_AES_128_CBC_SHA(0x008C, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_PSK_WITH_AES_256_CBC_SHA(0x008D, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_PSK_WITH_RC4_128_SHA(0x008E, CipherType.STREAM, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x008F, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x0090, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x0091, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_PSK_WITH_RC4_128_SHA(0x0092, CipherType.STREAM, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x0093, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x0094, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x0095, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_SEED_CBC_SHA(0x0096, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_DSS_WITH_SEED_CBC_SHA(0x0097, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_RSA_WITH_SEED_CBC_SHA(0x0098, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_DSS_WITH_SEED_CBC_SHA(0x0099, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DHE_RSA_WITH_SEED_CBC_SHA(0x009A, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_DH_anon_WITH_SEED_CBC_SHA(0x009B, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.SEED_CBC, HashAlgorithm.SHA1, false, false),
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0x00A0, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0x00A1, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0x00A4, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0x00A5, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_anon_WITH_AES_128_GCM_SHA256(0x00A6, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_AES_256_GCM_SHA384(0x00A7, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_AES_128_GCM_SHA256(0x00A8, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_256_GCM_SHA384(0x00A9, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0x00AA, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0x00AB, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0x00AC, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0x00AD, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_256_CBC_SHA384(0x00AF, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_NULL_SHA256(0x00B0, CipherType.STREAM, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_NULL_SHA384(0x00B1, CipherType.STREAM, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0x00B2, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0x00B3, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_NULL_SHA256(0x00B4, CipherType.STREAM, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_NULL_SHA384(0x00B5, CipherType.STREAM, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0x00B6, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0x00B7, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_NULL_SHA256(0x00B8, CipherType.STREAM, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_NULL_SHA384(0x00B9, CipherType.STREAM, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BA, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BB, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BC, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BD, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BE, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(0x00BF, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C0, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C1, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C2, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C3, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C4, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(0x00C5, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA256, false, false),
    TLS_SM4_GCM_SM3(0x00C6, CipherType.AEAD, null,
            CipherAlgorithm.SM4_GCM, HashAlgorithm.SM3, false, true),
    TLS_SM4_CCM_SM3(0x00C7, CipherType.AEAD, null,
            CipherAlgorithm.SM4_CCM, HashAlgorithm.SM3, false, true),
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF, false),
    TLS_AES_128_GCM_SHA256(0x1301, CipherType.AEAD, null,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, true),
    TLS_AES_256_GCM_SHA384(0x1302, CipherType.AEAD, null,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, true),
    TLS_CHACHA20_POLY1305_SHA256(0x1303, CipherType.AEAD, null,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, true),
    TLS_AES_128_CCM_SHA256(0x1304, CipherType.AEAD, null,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, true),
    TLS_AES_128_CCM_8_SHA256(0x1305, CipherType.AEAD, null,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, true),
    TLS_FALLBACK_SCSV(0x5600, false),
    TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_anon_WITH_NULL_SHA(0xC015, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016, CipherType.STREAM, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ANON,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(0xC01A, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(0xC01B, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_RSA,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(0xC01C, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_DSS,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA(0xC01D, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(0xC01E, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(0xC01F, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_DSS,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA(0xC020, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(0xC021, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(0xC022, CipherType.BLOCK, KeyExchangeAlgorithm.SRP_SHA_DSS,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_PSK_WITH_RC4_128_SHA(0xC033, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.RC4_128, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(0xC034, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.DES_EDE_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0xC035, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0xC036, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.AES_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(0xC038, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.AES_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_PSK_WITH_NULL_SHA(0xC039, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA1, false, false),
    TLS_ECDHE_PSK_WITH_NULL_SHA256(0xC03A, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_PSK_WITH_NULL_SHA384(0xC03B, CipherType.STREAM, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.NULL, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_ARIA_128_CBC_SHA256(0xC03C, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_ARIA_256_CBC_SHA384(0xC03D, CipherType.BLOCK, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256(0xC03E, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384(0xC03F, CipherType.BLOCK, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256(0xC040, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384(0xC041, CipherType.BLOCK, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256(0xC042, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384(0xC043, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC044, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC045, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256(0xC046, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384(0xC047, CipherType.BLOCK, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC048, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC049, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256(0xC04A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384(0xC04B, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256(0xC04C, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384(0xC04D, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256(0xC04E, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384(0xC04F, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_ARIA_128_GCM_SHA256(0xC050, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_ARIA_256_GCM_SHA384(0xC051, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC052, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC053, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256(0xC054, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384(0xC055, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256(0xC056, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384(0xC057, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256(0xC058, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384(0xC059, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256(0xC05A, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384(0xC05B, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05C, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05D, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256(0xC05E, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384(0xC05F, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256(0xC060, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384(0xC061, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256(0xC062, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384(0xC063, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_ARIA_128_CBC_SHA256(0xC064, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_ARIA_256_CBC_SHA384(0xC065, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC066, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC067, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256(0xC068, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384(0xC069, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_ARIA_128_GCM_SHA256(0xC06A, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_ARIA_256_GCM_SHA384(0xC06B, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256(0xC06C, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384(0xC06D, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256(0xC06E, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.ARIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384(0xC06F, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.ARIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256(0xC070, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.ARIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384(0xC071, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.ARIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC072, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC073, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC074, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC075, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC078, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC079, CipherType.BLOCK, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07A, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07B, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07C, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07D, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07E, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07F, CipherType.AEAD, KeyExchangeAlgorithm.DH_RSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC080, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC081, CipherType.AEAD, KeyExchangeAlgorithm.DHE_DSS,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC082, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC083, CipherType.AEAD, KeyExchangeAlgorithm.DH_DSS,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(0xC084, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(0xC085, CipherType.AEAD, KeyExchangeAlgorithm.DH_ANON,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC086, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC087, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC088, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC089, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_ECDSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08C, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08D, CipherType.AEAD, KeyExchangeAlgorithm.ECDH_RSA,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC08E, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC08F, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC090, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC091, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC092, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CAMELLIA_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC093, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CAMELLIA_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC094, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC095, CipherType.BLOCK, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC096, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC097, CipherType.BLOCK, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC098, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC099, CipherType.BLOCK, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC09A, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.CAMELLIA_128_CBC, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC09B, CipherType.BLOCK, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.CAMELLIA_256_CBC, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_AES_128_CCM(0xC09C, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_256_CCM(0xC09D, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_128_CCM(0xC09E, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_256_CCM(0xC09F, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_128_CCM_8(0xC0A0, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_RSA_WITH_AES_256_CCM_8(0xC0A1, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.AES_256_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0A2, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0A3, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.AES_256_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_128_CCM(0xC0A4, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_256_CCM(0xC0A5, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_AES_128_CCM(0xC0A6, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_AES_256_CCM(0xC0A7, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_128_CCM_8(0xC0A8, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_AES_256_CCM_8(0xC0A9, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.AES_256_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_PSK_DHE_WITH_AES_128_CCM_8(0xC0AA, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_PSK_DHE_WITH_AES_256_CCM_8(0xC0AB, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.AES_256_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xC0AC, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xC0AD, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_128_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(0xC0AF, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.AES_256_CCM_8, HashAlgorithm.SHA256, false, false),
    TLS_ECCPWD_WITH_AES_128_GCM_SHA256(0xC0B0, CipherType.AEAD, KeyExchangeAlgorithm.ECCPWD,
            CipherAlgorithm.AES_128_GCM, HashAlgorithm.SHA256, false, false),
    TLS_ECCPWD_WITH_AES_256_GCM_SHA384(0xC0B1, CipherType.AEAD, KeyExchangeAlgorithm.ECCPWD,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_ECCPWD_WITH_AES_128_CCM_SHA256(0xC0B2, CipherType.AEAD, KeyExchangeAlgorithm.ECCPWD,
            CipherAlgorithm.AES_128_CCM, HashAlgorithm.SHA256, false, false),
    TLS_ECCPWD_WITH_AES_256_CCM_SHA384(0xC0B3, CipherType.AEAD, KeyExchangeAlgorithm.ECCPWD,
            CipherAlgorithm.AES_256_CCM, HashAlgorithm.SHA384, false, false),

    // *************************************************************************
    // Unofficial cipher suites draft-mavrogiannopoulos-chacha-tls-01
    // These cipher suite are from a Draft and also don't have a prf hash algorithm
    // defined in their name but implicitly use SHA256
    // TODO the draft contaisn more
    UNOFFICIAL_TLS_RSA_WITH_CHACHA20_POLY1305(0xCC12, CipherType.AEAD, KeyExchangeAlgorithm.RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcc13, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcc14, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcc15, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC16, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC17, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC18, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    UNOFFICIAL_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_OLD(0xCC19, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    // *************************************************************************
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA8, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA9, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_ECDSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCAA, CipherType.AEAD, KeyExchangeAlgorithm.DHE_RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAB, CipherType.AEAD, KeyExchangeAlgorithm.PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAC, CipherType.AEAD, KeyExchangeAlgorithm.ECDHE_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAD, CipherType.AEAD, KeyExchangeAlgorithm.DHE_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256(0xCCAE, CipherType.AEAD, KeyExchangeAlgorithm.RSA_PSK,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256(0x16B7, CipherType.AEAD, KeyExchangeAlgorithm.CECPQ1_RSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0x16B8, CipherType.AEAD, KeyExchangeAlgorithm.CECPQ1_ECDSA,
            CipherAlgorithm.CHACHA20_POLY1305, HashAlgorithm.SHA256, false, false),
    TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384(0x16B9, CipherType.AEAD, KeyExchangeAlgorithm.CECPQ1_RSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384(0x16BA, CipherType.AEAD, KeyExchangeAlgorithm.CECPQ1_ECDSA,
            CipherAlgorithm.AES_256_GCM, HashAlgorithm.SHA384, false, false),
    TLS_RSA_WITH_RABBIT_CBC_SHA(0x00FD, CipherType.BLOCK, KeyExchangeAlgorithm.RSA, CipherAlgorithm.RABBIT_CBC,
            HashAlgorithm.SHA1, false, false), // non rfc, only wolfssl
    // GREASE constants
    GREASE_00(0x0A0A, true),
    GREASE_01(0x1A1A, true),
    GREASE_02(0x2A2A, true),
    GREASE_03(0x3A3A, true),
    GREASE_04(0x4A4A, true),
    GREASE_05(0x5A5A, true),
    GREASE_06(0x6A6A, true),
    GREASE_07(0x7A7A, true),
    GREASE_08(0x8A8A, true),
    GREASE_09(0x9A9A, true),
    GREASE_10(0xAAAA, true),
    GREASE_11(0xBABA, true),
    GREASE_12(0xCACA, true),
    GREASE_13(0xDADA, true),
    GREASE_14(0xEAEA, true),
    GREASE_15(0xFAFA, true),
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT(0xFF85, CipherType.BLOCK, KeyExchangeAlgorithm.GOSTR341112_256,
            CipherAlgorithm.GOST_28147_CNT_IMIT, HashAlgorithm.GOST_R3411_12, false, false),
    TLS_GOSTR341112_256_WITH_NULL_GOSTR3411(0xFF87, CipherType.BLOCK, KeyExchangeAlgorithm.GOSTR341112_256,
            CipherAlgorithm.NULL, HashAlgorithm.GOST_R3411_12, false, false),;

    private int value;

    public static final int EXPORT_SYMMETRIC_KEY_SIZE_BYTES = 5;

    private static final Map<Integer, CipherSuite> MAP;

    private final CipherType cipherType;
    private final CipherAlgorithm cipherAlgorithm;
    private final KeyExchangeAlgorithm keyExchangeAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final boolean grease;
    private final boolean tls13;
    private final boolean export;
    private boolean isRealCipherSuite;

    private CipherSuite(int value, CipherType cipherType, KeyExchangeAlgorithm keyExchangeAlgorithm,
            CipherAlgorithm cipherAlgorithm,
            HashAlgorithm hashAlgorithm, boolean isExport, boolean isTLS13) {
        this.value = value;
        this.grease = false;
        this.isRealCipherSuite = true;
        this.export = isExport;
        this.cipherType = cipherType;
        this.cipherAlgorithm = cipherAlgorithm;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.tls13 = isTLS13;
    }

    /**
     * This constructor is exclusivly for GREASE and other non-real cipher suites.
     * @param value
     * @param isGrease
     */
    private CipherSuite(int value, boolean isGrease) {
        this.value = value;
        this.grease = true;
        this.cipherAlgorithm = null;
        this.keyExchangeAlgorithm = null;
        this.hashAlgorithm = null;
        this.cipherType = null;
        this.isRealCipherSuite = false;
        this.export = false;
        this.tls13 = true;
    }

    static {
        MAP = new HashMap<>();
        for (CipherSuite c : CipherSuite.values()) {
            MAP.put(c.value, c);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length >= 2) {
            return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
        } else if (value.length == 1) {
            return value[0];
        } else {
            return 0;
        }
    }

    public static List<CipherSuite> getCipherSuites(byte[] values) {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        int pointer = 0;
        if (values.length % 2 != 0) {
            throw new UnknownCipherSuiteException("Last CipherSuit are unknown!");
        }
        while (pointer < values.length) {
            byte[] suite = new byte[2];
            suite[0] = values[pointer];
            suite[1] = values[pointer + 1];
            cipherSuites.add(getCipherSuite(suite));
            pointer += 2;
        }
        return cipherSuites;
    }

    public boolean isRealCipherSuite() {
        return isRealCipherSuite;
    }

    public static CipherSuite getCipherSuite(byte[] value) {
        return getCipherSuite(valueToInt(value));
    }

    public static CipherSuite getCipherSuite(int value) {
        CipherSuite cs = MAP.get(value);
        return cs;
    }

    public byte[] getByteValue() {
        return ArrayConverter.intToBytes(value, 2);
    }

    public int getValue() {
        return value;
    }

    /**
     * Returns true in case the cipher suite enforces ephemeral keys. This is the case for ECDHE and
     * DHE cipher suites.
     *
     * @return True if the cipher suite is Ephemeral
     */
    public boolean isEphemeral() {
        return keyExchangeAlgorithm.isKeyExchangeEphemeral() || this.isPWD() || this.isTls13();
    }

    public boolean isPskOrDhPsk() {
        if (!this.name().contains("RSA")) {
            return this.name().contains("PSK");
        } else {
            return false;
        }
    }

    public boolean isPsk() {
        return keyExchangeAlgorithm.isPsk();
    }

    public boolean isSrp() {
        return this.name().contains("SRP_");
    }

    public boolean isExport() {
        return this.name().contains("EXPORT");
    }

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }

    public boolean isExportSymmetricCipher() {
        return this.name().contains("DES40")
                || this.name().contains("RC4_40")
                || this.name().contains("RC2_CBC_40")
                || this.name().contains("DES_CBC_40");
    }

    /**
     * Returns true in case the cipher suite is a CBC cipher suite.
     *
     * @return True if the cipher suite is cbc
     */
    public boolean isCBC() {
        return (this.name().contains("_CBC"));
    }

    public Boolean isUsingPadding(ProtocolVersion protocolVersion) {
        switch (cipherType) {
            case STREAM:
                return false;
            case BLOCK:
                return true;
            case AEAD:
                if (protocolVersion != ProtocolVersion.TLS13) {
                    return false;
                } else {
                    return true;
                }
        }
        return null;
    }

    public boolean isUsingMac() {
        if (this.name().contains("NULL")) {
            String cipher = this.toString();
            if (cipher.endsWith("NULL")) {
                return false;
            }
            String[] hashFunctionNames = {
                    "MD5", "SHA", "SHA256", "SHA384", "SHA512", "IMIT", "GOSTR3411"
            };
            for (String hashFunction : hashFunctionNames) {
                if (cipher.endsWith(hashFunction)) {
                    return true;
                }
            }
            return false;
        }
        return (this.name().contains("_CBC")
                || this.name().contains("RC4")
                || this.name().contains("CNT"));
    }

    public boolean isSCSV() {
        return !isRealCipherSuite && !isGrease();
    }

    public boolean isGCM() {
        return (this.name().contains("_GCM"));
    }

    public boolean isCCM() {
        return (this.name().contains("_CCM"));
    }

    public boolean isCCM_8() {
        return (this.name().contains("_CCM_8"));
    }

    public boolean isOCB() {
        return (this.name().contains("_OCB"));
    }

    public boolean isSteamCipherWithIV() {
        return this.name().contains("28147_CNT");
    }

    public boolean isAEAD() {
        return this.isCCM() || this.isChachaPoly() || this.isGCM() || this.isOCB();
    }

    public boolean usesSHA384() {
        return this.name().endsWith("SHA384");
    }

    public boolean usesGOSTR3411() {
        return this.name().startsWith("TLS_GOSTR3410");
    }

    public boolean usesGOSTR34112012() {
        return this.name().startsWith("TLS_GOSTR3411");
    }

    public boolean usesStrictExplicitIv() {
        return (this.name().contains("CHACHA20_POLY1305"));
    }

    public boolean usesDH() {
        return (this.name().contains("_DH"));
    }

    /**
     * Returns true if the cipher suite is supported by the specified protocol version. TODO: this
     * is still very imprecise and must be improved with new ciphers.
     *
     * @param version The ProtocolVersion to check
     * @return True if the cipher suite is supported in the ProtocolVersion
     */
    public boolean isSupportedInProtocol(ProtocolVersion version) {
        if (version == ProtocolVersion.SSL3) {
            return SSL3_SUPPORTED_CIPHERSUITES.contains(this);
        }

        if (this.isTls13()) {
            return version == ProtocolVersion.TLS13;
        }

        if (this.isGCM()) {
            return version == ProtocolVersion.TLS12
                    || version == ProtocolVersion.DTLS12
                    || version == ProtocolVersion.TLS13;
        }

        if (this.name().endsWith("256")
                || this.name().endsWith("384")
                || this.isCCM()
                || this.isCCM_8()) {
            return ((version == ProtocolVersion.TLS12) || (version == ProtocolVersion.DTLS12));
        }
        if (this.name().contains("IDEA")
                || this.name().contains("_DES")
                || this.isExportSymmetricCipher()) {
            return !((version == ProtocolVersion.TLS12) || (version == ProtocolVersion.DTLS12));
        }

        return true;
    }

    @SuppressWarnings("SpellCheckingInspection")
    public static final Set<CipherSuite> SSL3_SUPPORTED_CIPHERSUITES = Collections.unmodifiableSet(
            new HashSet<>(
                    Arrays.asList(
                            TLS_NULL_WITH_NULL_NULL,
                            TLS_RSA_WITH_NULL_MD5,
                            TLS_RSA_WITH_NULL_SHA,
                            TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                            TLS_RSA_WITH_RC4_128_MD5,
                            TLS_RSA_WITH_RC4_128_SHA,
                            TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                            TLS_RSA_WITH_IDEA_CBC_SHA,
                            TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_RSA_WITH_DES_CBC_SHA,
                            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                            TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_DH_DSS_WITH_DES_CBC_SHA,
                            TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                            TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_DH_RSA_WITH_DES_CBC_SHA,
                            TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                            TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_DHE_DSS_WITH_DES_CBC_SHA,
                            TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                            TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_DHE_RSA_WITH_DES_CBC_SHA,
                            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                            TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                            TLS_DH_anon_WITH_RC4_128_MD5,
                            TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                            TLS_DH_anon_WITH_DES_CBC_SHA,
                            TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                            TLS_ECCPWD_WITH_AES_128_CCM_SHA256,
                            TLS_ECCPWD_WITH_AES_128_GCM_SHA256,
                            TLS_ECCPWD_WITH_AES_256_CCM_SHA384,
                            TLS_ECCPWD_WITH_AES_256_GCM_SHA384)));

    public static List<CipherSuite> getImplemented() {
        List<CipherSuite> list = new LinkedList<>();
        list.add(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_RSA_WITH_NULL_MD5);
        list.add(TLS_RSA_WITH_NULL_SHA);
        list.add(TLS_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_RSA_WITH_IDEA_CBC_SHA);
        list.add(TLS_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_RSA_WITH_RC4_128_MD5);
        list.add(TLS_RSA_WITH_RC4_128_SHA);
        list.add(TLS_RSA_WITH_AES_128_CCM);
        list.add(TLS_RSA_WITH_AES_256_CCM);
        list.add(TLS_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
        list.add(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_DH_anon_WITH_RC4_128_MD5);
        list.add(TLS_DH_anon_WITH_DES_CBC_SHA);
        list.add(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_anon_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_anon_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_DH_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_AES_128_CCM);
        list.add(TLS_DHE_RSA_WITH_AES_256_CCM);
        list.add(TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_DSS_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
        list.add(TLS_AES_128_GCM_SHA256);
        list.add(TLS_AES_256_GCM_SHA384);
        list.add(TLS_CHACHA20_POLY1305_SHA256);
        list.add(TLS_AES_128_CCM_SHA256);
        list.add(TLS_AES_128_CCM_8_SHA256);
        list.add(TLS_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_PSK_DHE_WITH_AES_128_CCM_8);
        list.add(TLS_PSK_DHE_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_AES_128_CCM);
        list.add(TLS_PSK_WITH_AES_128_CCM_8);
        list.add(TLS_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_AES_256_CCM);
        list.add(TLS_PSK_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_RC4_128_SHA);
        list.add(TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_128_CCM);
        list.add(TLS_DHE_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_DHE_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_AES_256_CCM);
        list.add(TLS_DHE_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_RC4_128_SHA);
        list.add(TLS_DH_RSA_WITH_DES_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_DES_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_RC4_128_SHA);
        list.add(TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_128_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_RSA_WITH_SEED_CBC_SHA);
        list.add(TLS_RSA_PSK_WITH_AES_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_AES_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_RSA_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_anon_WITH_NULL_SHA);
        list.add(TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        list.add(TLS_SRP_SHA_WITH_AES_256_CBC_SHA);
        list.add(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384);
        list.add(TLS_PSK_WITH_NULL_SHA);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA);
        list.add(TLS_RSA_WITH_NULL_SHA256);
        list.add(UNOFFICIAL_TLS_ECDH_ECDSA_WITH_NULL_SHA);
        list.add(TLS_PSK_WITH_NULL_SHA256);
        list.add(TLS_PSK_WITH_NULL_SHA384);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA256);
        list.add(TLS_DHE_PSK_WITH_NULL_SHA384);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA256);
        list.add(TLS_RSA_PSK_WITH_NULL_SHA384);
        list.add(TLS_ECDH_ECDSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        list.add(TLS_ECDH_RSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_RSA_WITH_NULL_SHA);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_NULL_SHA384);
        list.add(TLS_DH_DSS_WITH_DES_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_DES_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_NULL_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_RC4_128_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_DES_CBC_SHA);
        list.add(UNOFFICIAL_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_SEED_CBC_SHA);
        list.add(TLS_DHE_DSS_WITH_SEED_CBC_SHA);
        list.add(TLS_DH_anon_WITH_SEED_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_AES_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256);
        list.add(TLS_ECDH_anon_WITH_RC4_128_SHA);
        list.add(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        list.add(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        list.add(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);
        list.add(TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DH_anon_WITH_ARIA_128_CBC_SHA256);
        list.add(TLS_DH_anon_WITH_ARIA_256_CBC_SHA384);
        list.add(TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_ARIA_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_ARIA_256_GCM_SHA384);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256);
        list.add(TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384);
        list.add(TLS_GOSTR341001_WITH_28147_CNT_IMIT);
        list.add(TLS_GOSTR341001_WITH_NULL_GOSTR3411);
        list.add(TLS_GOSTR341112_256_WITH_28147_CNT_IMIT);
        list.add(TLS_GOSTR341112_256_WITH_NULL_GOSTR3411);
        list.add(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        list.add(TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        list.add(TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        list.add(TLS_RSA_WITH_AES_128_CCM_8);
        list.add(TLS_RSA_WITH_AES_256_CCM_8);
        list.add(TLS_DHE_RSA_WITH_AES_128_CCM_8);
        list.add(TLS_DHE_RSA_WITH_AES_256_CCM_8);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        list.add(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
        list.add(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_RSA_WITH_CHACHA20_POLY1305);
        list.add(UNOFFICIAL_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        list.add(UNOFFICIAL_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(UNOFFICIAL_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_OLD);
        list.add(TLS_RSA_EXPORT_WITH_RC4_40_MD5);
        list.add(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        list.add(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        list.add(TLS_SM4_GCM_SM3);
        list.add(TLS_SM4_CCM_SM3);
        list.add(TLS_NULL_WITH_NULL_NULL);
        return list;
    }

    public static List<CipherSuite> getEsniImplemented() {
        List<CipherSuite> list = new LinkedList<>();
        list.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        list.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        list.add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_SHA256);
        list.add(CipherSuite.TLS_AES_128_CCM_8_SHA256);
        return list;
    }

    public static List<CipherSuite> getAllCipherSuites() {
        List<CipherSuite> list = new LinkedList<>();
        list.addAll(Arrays.asList(values()));
        return list;
    }

    public static List<CipherSuite> getTls13CipherSuites() {
        return getAllCipherSuites().stream().filter(CipherSuite::isTls13).collect(Collectors.toList());
    }

    public static List<CipherSuite> getImplementedTls13CipherSuites() {
        return getImplemented().stream().filter(CipherSuite::isTls13).collect(Collectors.toList());
    }

    public static List<CipherSuite> getNotImplemented() {
        List<CipherSuite> notImplemented = new LinkedList<>();
        for (CipherSuite suite : values()) {
            if (!getImplemented().contains(suite)) {
                notImplemented.add(suite);
            }
        }
        return notImplemented;
    }

    /**
     * Returns true if the cipher suite a TLS 1.3 cipher suite
     *
     * @return True if the Ciphersuite is supported in TLS 1.3
     */
    public boolean isTls13() {
        return tls13;
    }

    public CipherType getCipherType() {
        return cipherType;
    }

    public CipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public boolean isImplemented() {
        return getImplemented().contains(this);
    }

    public boolean isSHA1() {
        return hashAlgorithm == HashAlgorithm.SHA1;
    }

    public boolean isSHA256() {
        return hashAlgorithm == HashAlgorithm.SHA256;
    }

    public boolean isSHA384() {
        return hashAlgorithm == HashAlgorithm.SHA384;
    }

    public boolean isSHA512() {
        return hashAlgorithm == HashAlgorithm.SHA512;
    }

    public boolean isChachaPoly() {
        return cipherAlgorithm == CipherAlgorithm.CHACHA20_POLY1305;
    }

    public boolean isECDSA() {
        return keyExchangeAlgorithm != null && keyExchangeAlgorithm.isEcdsa();
    }

    public boolean isAnon() {
        return keyExchangeAlgorithm != null && keyExchangeAlgorithm.isAnon();
    }

    public boolean isNull() {
        return this.name().toLowerCase().contains("null");
    }

    public boolean isPWD() {
        return keyExchangeAlgorithm == KeyExchangeAlgorithm.ECCPWD;
    }

    public boolean isDSS() {
        return keyExchangeAlgorithm != null && keyExchangeAlgorithm.isDss();
    }

    public boolean isGOST() {
        return keyExchangeAlgorithm != null && keyExchangeAlgorithm.isGost();
    }

    public boolean isSM() {
        return this.name().contains("SM");
    }

    // Note: We don't consider DES as weak for these purposes.
    public boolean isWeak() {
        return this.isExport() || this.isExportSymmetricCipher() || this.isAnon() || this.isNull();
    }

    public boolean requiresServerCertificateMessage() {
        return !this.isSrp() && !this.isPskOrDhPsk() && !this.isAnon() && !this.isPWD();
    }
}
