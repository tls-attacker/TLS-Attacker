/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Computes message digest for two algorithms at once, typically for MD5 and
 * SHA1 for TLS 1.0. At the end it returns MD5(value) || SHA1(value). For TLS
 * 1.2 SHA256 is used, as described in the RFC.
 */
public class MessageDigestCollector {

    private static final Logger LOGGER = LogManager.getLogger();

    private ByteArrayOutputStream stream;

    /**
     * Default constructor.
     */
    public MessageDigestCollector() {
        stream = new ByteArrayOutputStream();
    }

    public void append(byte[] bytes) {
        try {
            stream.write(bytes);
        } catch (IOException ex) {
            // Should never fail
            LOGGER.error("Could not append bytes to Stream", ex);
        }
    }

    public byte[] digest(ProtocolVersion version, CipherSuite suite) {
        try {
            MessageDigest hash1;
            MessageDigest hash2 = null;
            DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(version, suite);
            if (null == algorithm) {
                hash1 = MessageDigest.getInstance(algorithm.getJavaName());
            } else {
                switch (algorithm) {
                    case SSL_DIGEST:
                        throw new RuntimeException("Unsupported DigestAlgorithm SSL_DIGEST");
                    case LEGACY:
                        hash1 = MessageDigest.getInstance("MD5");
                        hash2 = MessageDigest.getInstance("SHA-1");
                        break;
                    default:
                        hash1 = MessageDigest.getInstance(algorithm.getJavaName());
                        break;
                }
            }
            hash1.update(stream.toByteArray());
            byte[] digest = hash1.digest();
            if (hash2 != null) {
                hash2.update(stream.toByteArray());
                byte[] d2 = hash2.digest();
                digest = ArrayConverter.concatenate(digest, d2);
            }
            return digest;
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("Unsupported Hash algorithm!");
        }

    }

    public void reset() {
        stream = new ByteArrayOutputStream();
    }

    public byte[] getRawBytes() {
        return stream.toByteArray();
    }

    public void setRawBytes(byte[] rawBytes) {
        reset();
        try {
            if (rawBytes != null) {
                stream.write(rawBytes);
            }
        } catch (IOException ex) {
            // Should never fail
            LOGGER.error("Could not set RawBytes in MessageDigestCollector", ex);
        }
    }
}
