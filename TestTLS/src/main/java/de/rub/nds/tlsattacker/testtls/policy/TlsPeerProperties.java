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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TlsPeerProperties {

    public static Logger LOGGER = LogManager.getLogger(TlsPeerProperties.class);

    Set<ProtocolVersion> protocolVersions;

    Set<CipherAlgorithm> ciphers;

    Set<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

    Set<SignatureAlgorithm> signatureAlgorithms;

    Set<HashAlgorithm> hashAlgorithms;

    Set<NamedCurve> namedCurves;

    Set<MacAlgorithm> macAlgorithms;

    int minimumDhGroupSize = 0;

    int minimumEcdhGroupSize = 0;

    int minimumRsaBits = 0;

    boolean usingCiphersuitePreferenes;

    public TlsPeerProperties() {
        protocolVersions = new HashSet<>();
    }

    public void addProtocolVersion(ProtocolVersion pv) {
        protocolVersions.add(pv);
    }

    public Set<ProtocolVersion> getProtocolVersions() {
        return protocolVersions;
    }

    public void setProtocolVersions(Set<ProtocolVersion> protocolVersions) {
        this.protocolVersions = protocolVersions;
    }

    public Set<CipherAlgorithm> getCiphers() {
        return ciphers;
    }

    public void setCiphers(Set<CipherAlgorithm> ciphers) {
        this.ciphers = ciphers;
    }

    public Set<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithms() {
        return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(Set<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
        this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    public Set<SignatureAlgorithm> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    public void setSignatureAlgorithms(Set<SignatureAlgorithm> signatureAlgorithms) {
        this.signatureAlgorithms = signatureAlgorithms;
        if (hashAlgorithms != null) {
            constructSignatureAndHashAlgorithmsList();
        }
    }

    public Set<HashAlgorithm> getHashAlgorithms() {
        return hashAlgorithms;
    }

    public void setHashAlgorithms(Set<HashAlgorithm> hashAlgorithms) {
        this.hashAlgorithms = hashAlgorithms;
        if (signatureAlgorithms != null) {
            constructSignatureAndHashAlgorithmsList();
        }
    }

    public Set<NamedCurve> getNamedCurves() {
        return namedCurves;
    }

    public void setNamedCurves(Set<NamedCurve> namedCurves) {
        this.namedCurves = namedCurves;
    }

    public int getMinimumDhGroupSize() {
        return minimumDhGroupSize;
    }

    public void setMinimumDhGroupSize(int minimumDhGroupSize) {
        if (this.minimumDhGroupSize == 0 || minimumDhGroupSize < this.minimumDhGroupSize) {
            this.minimumDhGroupSize = minimumDhGroupSize;
        }
    }

    public int getMinimumEcdhGroupSize() {
        return minimumEcdhGroupSize;
    }

    public void setMinimumEcdhGroupSize(int minimumEcdhGroupSize) {
        if (this.minimumEcdhGroupSize == 0 || minimumEcdhGroupSize < this.minimumEcdhGroupSize) {
            this.minimumEcdhGroupSize = minimumEcdhGroupSize;
        }
    }

    public int getMinimumRsaBits() {
        return minimumRsaBits;
    }

    public void setMinimumRsaBits(int minimumRsaBits) {
        if (this.minimumRsaBits == 0 || minimumRsaBits < this.minimumRsaBits) {
            this.minimumRsaBits = minimumRsaBits;
        }
    }

    public boolean isUsingCiphersuitePreferenes() {
        return usingCiphersuitePreferenes;
    }

    public void setUsingCiphersuitePreferenes(boolean usingCiphersuitePreferenes) {
        this.usingCiphersuitePreferenes = usingCiphersuitePreferenes;
    }

    public Set<MacAlgorithm> getMacAlgorithms() {
        return macAlgorithms;
    }

    public void setMacAlgorithms(Set<MacAlgorithm> macAlgorithms) {
        this.macAlgorithms = macAlgorithms;
    }

    private void constructSignatureAndHashAlgorithmsList() {
        signatureAndHashAlgorithms = new HashSet<>();
        for (SignatureAlgorithm sa : signatureAlgorithms) {
            for (HashAlgorithm ha : hashAlgorithms) {
                signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(sa, ha));
            }
        }
    }

    public boolean compliesPolicy(TlsPeerProperties policy) {
        boolean result = true;
        if (minimumDhGroupSize < policy.getMinimumDhGroupSize()) {
            LOGGER.error("minimum dh group size not achieved");
            result = false;
        }
        if (minimumEcdhGroupSize < policy.getMinimumEcdhGroupSize()) {
            LOGGER.error("minimum ecdh group size not achieved");
            result = false;
        }
        if (minimumRsaBits < policy.getMinimumRsaBits()) {
            LOGGER.error("minimum rsa key bits not provided");
            result = false;
        }
        if (!protocolVersions.equals(policy.getProtocolVersions())) {
            LOGGER.error("Protocol versions are not equal");
            result = false;
        }
        if (!ciphers.equals(policy.getCiphers())) {
            LOGGER.error("The list of provided ciphers is different from the configured ciphers");
            result = false;
        }
        if (!signatureAndHashAlgorithms.equals(policy.getSignatureAndHashAlgorithms())) {
            LOGGER.error("The list of signature and hash algorithms is different from the configured signature and hash algorithms");
            result = false;
        }
        if (!namedCurves.equals(policy.getNamedCurves())) {
            LOGGER.error("The list of named curves is different from the configured named curves");
            result = false;
        }
        if (!macAlgorithms.equals(policy.getMacAlgorithms())) {
            LOGGER.error("The list of MAC algorithms is different from the configured list of MAC algorithms");
            result = false;
        }
        return result;
    }

}
