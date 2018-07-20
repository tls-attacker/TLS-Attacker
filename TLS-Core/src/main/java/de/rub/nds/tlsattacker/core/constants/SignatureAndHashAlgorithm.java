/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.io.Serializable;
import java.util.Objects;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Construction of a hash and signature algorithm. Very confusing, consists of
 * two bytes, the first is hash algorithm: {HashAlgorithm, SignatureAlgorithm}
 */
public class SignatureAndHashAlgorithm implements Serializable {

    protected static final Logger LOGGER = LogManager.getLogger(SignatureAndHashAlgorithm.class.getName());

    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(byte[] value) {
        return new SignatureAndHashAlgorithm(value);
    }

    public static SignatureAndHashAlgorithm getRandom(Random random) {
        return new SignatureAndHashAlgorithm(SignatureAlgorithm.getRandom(random), HashAlgorithm.getRandom(random));
    }

    public static SignatureAndHashAlgorithm[] values() {
        int size = SignatureAlgorithm.values().length * HashAlgorithm.values().length;
        SignatureAndHashAlgorithm[] result = new SignatureAndHashAlgorithm[size];
        int pos = 0;
        for (SignatureAlgorithm sa : SignatureAlgorithm.values()) {
            for (HashAlgorithm ha : HashAlgorithm.values()) {
                result[pos] = new SignatureAndHashAlgorithm(sa, ha);
                pos++;
            }
        }
        return result;
    }

    private SignatureAlgorithm signatureAlgorithm;

    private HashAlgorithm hashAlgorithm;

    public SignatureAndHashAlgorithm() {

    }

    public SignatureAndHashAlgorithm(SignatureAndHashAlgorithm other) {
        signatureAlgorithm = other.signatureAlgorithm;
        hashAlgorithm = other.hashAlgorithm;
    }

    public SignatureAndHashAlgorithm(byte[] value) {
        if (value == null || value.length != 2) {
            throw new ConfigurationException("SignatureAndHashAlgorithm always consists of two bytes, but found "
                    + ArrayConverter.bytesToHexString(value));
        }
        if (value[0] == (byte) 8) {
            if (value[1] == 7) {
                hashAlgorithm = HashAlgorithm.NONE;
                signatureAlgorithm = SignatureAlgorithm.X25519;
            } else if (value[1] == 8) {
                hashAlgorithm = HashAlgorithm.NONE;
                signatureAlgorithm = SignatureAlgorithm.X448;
            } else if (value[1] == 9) {
                hashAlgorithm = HashAlgorithm.SHA256;
                signatureAlgorithm = SignatureAlgorithm.RSA_PSS;
            } else if (value[1] == 0xA) {
                hashAlgorithm = HashAlgorithm.SHA384;
                signatureAlgorithm = SignatureAlgorithm.RSA_PSS;
            } else if (value[1] == 0xB) {
                hashAlgorithm = HashAlgorithm.SHA512;
                signatureAlgorithm = SignatureAlgorithm.RSA_PSS;
            }
            hashAlgorithm = HashAlgorithm.getHashAlgorithm(value[1]);
            signatureAlgorithm = SignatureAlgorithm.getSignatureAlgorithm(value[0]);
        } else {
            hashAlgorithm = HashAlgorithm.getHashAlgorithm(value[0]);
            signatureAlgorithm = SignatureAlgorithm.getSignatureAlgorithm(value[1]);
        }
        if (hashAlgorithm == null) {
            LOGGER.warn("Could not parse " + ArrayConverter.bytesToHexString(value)
                    + " into a HashAlgorithm. Using NONE");
            hashAlgorithm = HashAlgorithm.NONE;
        }
        if (signatureAlgorithm == null) {
            LOGGER.warn("Could not parse " + ArrayConverter.bytesToHexString(value)
                    + " into a SignatureAlgorithm. Using ANONYMOUS");
            signatureAlgorithm = SignatureAlgorithm.ANONYMOUS;
        }
    }

    public SignatureAndHashAlgorithm(SignatureAlgorithm sigAlgorithm, HashAlgorithm hashAlgorithm) {
        this.signatureAlgorithm = sigAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public byte[] getByteValue() {
        // TODO Clean up this madness
        if (signatureAlgorithm == SignatureAlgorithm.X25519) {
            return new byte[] { 8, 7 };
        } else if (signatureAlgorithm == SignatureAlgorithm.X448) {
            return new byte[] { 8, 8 };
        } else if (signatureAlgorithm == SignatureAlgorithm.RSA_PSS) {
            if (hashAlgorithm == HashAlgorithm.SHA256) {
                return new byte[] { 8, 9 };
            } else if (hashAlgorithm == HashAlgorithm.SHA384) {
                return new byte[] { 8, 0xA };
            } else if (hashAlgorithm == HashAlgorithm.SHA512) {
                return new byte[] { 8, 0xB };
            }
            return new byte[] { signatureAlgorithm.getValue(), hashAlgorithm.getValue() };
        } else {
            return new byte[] { hashAlgorithm.getValue(), signatureAlgorithm.getValue() };
        }
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getJavaName() {
        String hashAlgorithmName = hashAlgorithm.getJavaName().replace("-", "");
        String signatureAlgorithmName = signatureAlgorithm.getJavaName();
        return hashAlgorithmName + "with" + signatureAlgorithmName;
    }

    @Override
    public String toString() {
        return signatureAlgorithm + "-" + hashAlgorithm;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 47 * hash + Objects.hashCode(this.signatureAlgorithm);
        hash = 47 * hash + Objects.hashCode(this.hashAlgorithm);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm) obj;
        return this.hashAlgorithm == other.hashAlgorithm && this.signatureAlgorithm == other.signatureAlgorithm;
    }

}
