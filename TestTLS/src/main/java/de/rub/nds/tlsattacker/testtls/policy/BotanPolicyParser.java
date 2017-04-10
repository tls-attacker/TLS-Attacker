/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.policy;

import de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * Allows one to explicitly verify their configuration, based on a Botan
 * tlsProperties file structure. See for example:
 * https://github.com/randombit/botan/tree/master/tls-tlsProperties
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BotanPolicyParser {

    public static Logger LOGGER = LogManager.getLogger("BotanPolicyParser");

    private final String delimiter;

    private final TlsPeerProperties tlsProperties;

    public BotanPolicyParser() {
        delimiter = "\\n+\\s*";
        tlsProperties = new TlsPeerProperties();
    }

    public void parsePolicy(String filename) throws FileNotFoundException {
        File policyFile = new File(filename);
        try (Scanner input = new Scanner(policyFile)) {
            input.useDelimiter(delimiter);
            while (input.hasNext()) {
                String line = input.next();
                String rule[] = line.split("\\s*[=]\\s*");
                if (rule.length != 2) {
                    LOGGER.error("Invalid policy rule: {}", line);
                    continue;
                }
                switch (rule[0]) {
                    case "allow_tls10":
                        if (Boolean.parseBoolean(rule[1])) {
                            tlsProperties.addProtocolVersion(ProtocolVersion.TLS10);
                        }
                        break;
                    case "allow_tls11":
                        if (Boolean.parseBoolean(rule[1])) {
                            tlsProperties.addProtocolVersion(ProtocolVersion.TLS11);
                        }
                        break;
                    case "allow_tls12":
                        if (Boolean.parseBoolean(rule[1])) {
                            tlsProperties.addProtocolVersion(ProtocolVersion.TLS12);
                        }
                        break;
                    case "server_uses_own_ciphersuite_preferences":
                        tlsProperties.setUsingCiphersuitePreferenes(Boolean.parseBoolean(rule[1]));
                        break;
                    case "minimum_dh_group_size":
                        tlsProperties.setMinimumDhGroupSize(Integer.parseInt(rule[1]));
                        break;
                    case "minimum_ecdh_group_size":
                        tlsProperties.setMinimumEcdhGroupSize(Integer.parseInt(rule[1]));
                        break;
                    case "minimum_rsa_bits":
                        tlsProperties.setMinimumRsaBits(Integer.parseInt(rule[1]));
                        break;
                    case "ciphers":
                        tlsProperties.setCiphers(parseBotanCiphers(rule[1]));
                        break;
                    case "signature_hashes":
                        tlsProperties.setHashAlgorithms(parseBotanHashAlgorithms(rule[1]));
                        break;
                    case "signature_methods":
                        tlsProperties.setSignatureAlgorithms(parseBotanSignatureAlgorithms(rule[1]));
                        break;
                    case "macs":
                        tlsProperties.setMacAlgorithms(parseBotanMacAlgorithms(rule[1]));
                        break;
                    case "ecc_curves":
                        tlsProperties.setNamedCurves(parseBotanCurves(rule[1]));
                        break;

                    default:
                        LOGGER.info("Currently cannot handle rule " + rule[0]);
                }
            }
        }
    }

    private Set<CipherAlgorithm> parseBotanCiphers(String ciphers) {
        Set<CipherAlgorithm> result = new HashSet<>();
        String[] cs = ciphers.split("\\s+");
        for (String c : cs) {
            result.add(parseCipherAlgorithm(c));
        }
        return result;
    }

    private Set<HashAlgorithm> parseBotanHashAlgorithms(String hashes) {
        Set<HashAlgorithm> result = new HashSet();
        String[] cs = hashes.split("\\s+");
        for (String c : cs) {
            result.add(parseHashAlgorithm(c));
        }
        return result;
    }

    private Set<SignatureAlgorithm> parseBotanSignatureAlgorithms(String signatures) {
        Set<SignatureAlgorithm> result = new HashSet();
        String[] sig = signatures.split("\\s+");
        for (String s : sig) {
            result.add(parseSignatureAlgorithm(s));
        }
        return result;
    }

    private Set<MacAlgorithm> parseBotanMacAlgorithms(String macs) {
        Set<MacAlgorithm> result = new HashSet();
        String[] cs = macs.split("\\s+");
        for (String c : cs) {
            result.add(parseMacAlgorithm(c));
        }
        return result;
    }

    private Set<NamedCurve> parseBotanCurves(String curves) {
        Set<NamedCurve> result = new HashSet();
        String[] cs = curves.split("\\s+");
        for (String c : cs) {
            result.add(parseNamedCurve(c));
        }
        return result;
    }

    private CipherAlgorithm parseCipherAlgorithm(String botanCipher) {
        switch (botanCipher) {
            case "AES-256/GCM":
                return CipherAlgorithm.AES_256_GCM;
            case "AES-128/GCM":
                return CipherAlgorithm.AES_128_GCM;
            case "ChaCha20Poly1305":
                return CipherAlgorithm.ChaCha20Poly1305;
            case "AES-256/CCM":
            case "AES-256/CCM(8)":
                return CipherAlgorithm.AES_256_CCM;
            case "AES-128/CCM":
            case "AES-128/CCM(8)":
                return CipherAlgorithm.AES_128_CCM;
            case "AES-256":
                return CipherAlgorithm.AES_256_CBC;
            case "AES-128":
                return CipherAlgorithm.AES_128_CBC;
            case "SEED":
                return CipherAlgorithm.SEED_CBC;
            case "3DES":
                return CipherAlgorithm.DES_EDE_CBC;
            default:
                LOGGER.error("Cannot find the following cipher algorithm: " + botanCipher);
                return CipherAlgorithm.NULL;
        }

    }

    private HashAlgorithm parseHashAlgorithm(String botanHash) {
        // same hash algorithms in botan and java
        for (HashAlgorithm ha : HashAlgorithm.values()) {
            if (ha.getJavaName().equalsIgnoreCase(botanHash)) {
                return ha;
            }
        }
        LOGGER.error("Cannot find the following cipher algorithm: " + botanHash);
        return HashAlgorithm.NONE;
    }

    private MacAlgorithm parseMacAlgorithm(String botanMac) {
        switch (botanMac) {
            case "AEAD":
                return MacAlgorithm.AEAD;
            case "SHA-512":
                return MacAlgorithm.HMAC_SHA512;
            case "SHA-384":
                return MacAlgorithm.HMAC_SHA384;
            case "SHA-256":
                return MacAlgorithm.HMAC_SHA256;
            case "SHA-1":
                return MacAlgorithm.HMAC_SHA1;
            default:
                LOGGER.error("Cannot find the following MAC algorithm: " + botanMac);
                return MacAlgorithm.NULL;
        }
    }

    private SignatureAlgorithm parseSignatureAlgorithm(String botanSignature) {
        // same signature algorithms in botan and in tls attacker
        return SignatureAlgorithm.valueOf(botanSignature);
    }

    private NamedCurve parseNamedCurve(String botanCurve) {
        // nearly the same curves in botan and in tls attacker
        switch (botanCurve) {
            case "brainpool512r1":
                return NamedCurve.BRAINPOOLP512R1;
            case "brainpool384r1":
                return NamedCurve.BRAINPOOLP384R1;
            case "brainpool256r1":
                return NamedCurve.BRAINPOOLP256R1;
            default:
                for (NamedCurve nc : NamedCurve.values()) {
                    if (nc.toString().equalsIgnoreCase(botanCurve)) {
                        return nc;
                    }
                }
                LOGGER.error("Cannot find the following Curve : " + botanCurve);
                return NamedCurve.NONE;
        }
    }

    public TlsPeerProperties getTlsProperties() {
        return tlsProperties;
    }

}