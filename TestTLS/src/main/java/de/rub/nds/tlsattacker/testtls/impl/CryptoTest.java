/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CryptoTest extends HandshakeTest {

    private final HashMap<ProtocolVersion, List<CipherSuite>> supportedCipherSuites;

    private final Set<CipherSuite> allSupportedCipherSuites;

    private final Set<KeyExchangeAlgorithm> supportedKeyExchangeAlgorithms;

    private final Set<PRFAlgorithm> supportedPRFAlgorithms;

    private final Set<CipherAlgorithm> supportedCipherAlgorithms;

    private final Set<MacAlgorithm> supportedMacAlgorithms;

    /**
     * Minimum size of the EC certificate provided by the server. ECDHE keys are
     * not considered here
     */
    private int minimumECKeySize;

    private int minimumDHGroupSize;

    private int minimumRSAKeySize;

    public CryptoTest(ConfigHandler configHandler, TestServerConfig serverConfig) {
        super(configHandler, serverConfig);
        supportedCipherSuites = new HashMap<>();
        allSupportedCipherSuites = new HashSet<>();
        supportedKeyExchangeAlgorithms = new HashSet<>();
        supportedPRFAlgorithms = new HashSet<>();
        supportedCipherAlgorithms = new HashSet<>();
        supportedMacAlgorithms = new HashSet<>();
    }

    @Override
    public void startTests() {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (pv == ProtocolVersion.DTLS10 || pv == ProtocolVersion.DTLS12) {
                continue;
            }
            for (CipherSuite cs : CipherSuite.values()) {
                TlsConfig tlsConfig = configHandler.initialize(serverConfig);
                tlsConfig.setHighestProtocolVersion(pv);
                tlsConfig.setSupportedCiphersuites(Collections.singletonList(cs));
                boolean success = false;
                try {
                    success = executeHandshake(tlsConfig);
                    if (success) {
                        analyzeHandshake(pv, cs);
                    }
                } catch (Exception ex) {
                    LOGGER.error(ex.getLocalizedMessage());
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
            }
        }

        buildResultString();
    }

    private void analyzeHandshake(ProtocolVersion pv, CipherSuite cs) {
        if (!supportedCipherSuites.containsKey(pv)) {
            supportedCipherSuites.put(pv, new LinkedList<CipherSuite>());
        }
        supportedCipherSuites.get(pv).add(cs);
        allSupportedCipherSuites.add(cs);
        supportedCipherAlgorithms.add(AlgorithmResolver.getCipher(cs));
        supportedKeyExchangeAlgorithms.add(AlgorithmResolver.getKeyExchangeAlgorithm(cs));
        supportedMacAlgorithms.add(AlgorithmResolver.getMacAlgorithm(cs));
        supportedPRFAlgorithms.add(AlgorithmResolver.getPRFAlgorithm(pv, cs));
        if (lastTlsContext.getServerDHParameters() != null) {
            LOGGER.info("DH parameter public key size: {}", lastTlsContext.getServerDHParameters().getPublicKey()
                    .getY().bitLength());
            int groupSize = lastTlsContext.getServerDHParameters().getPublicKey().getParameters().getP().bitLength();
            if (minimumDHGroupSize == 0 || groupSize < minimumDHGroupSize) {
                minimumDHGroupSize = groupSize;
            }
        }
        if (lastTlsContext.getX509ServerCertificateObject() != null) {
            String algorithm = lastTlsContext.getX509ServerCertificateObject().getPublicKey().getAlgorithm();
            switch (algorithm) {
                case "RSA":
                    RSAPublicKey rsaPK = (RSAPublicKey) lastTlsContext.getX509ServerCertificateObject().getPublicKey();
                    int rsaSize = rsaPK.getModulus().bitLength();
                    LOGGER.info("RSA certificate public key size: {}", rsaSize);
                    if (minimumRSAKeySize == 0 || rsaSize < minimumRSAKeySize) {
                        minimumRSAKeySize = rsaSize;
                    }
                    break;
                case "EC":
                    ECPublicKey ecPK = (ECPublicKey) lastTlsContext.getX509ServerCertificateObject().getPublicKey();
                    int ecSize = ecPK.getParams().getCurve().getField().getFieldSize();
                    LOGGER.info("ECDSA certificate public key size: {}" + ecSize);
                    if (minimumECKeySize == 0 || ecSize < minimumECKeySize) {
                        minimumECKeySize = ecSize;
                    }
                    break;
                case "DSA":
                    DSAPublicKey dhPK = (DSAPublicKey) lastTlsContext.getX509ServerCertificateObject().getPublicKey();
                    int dhSize = dhPK.getParams().getP().bitLength();
                    LOGGER.info("DSA certificate public key size: " + dhSize);
                    if (minimumDHGroupSize == 0 || dhSize < minimumDHGroupSize) {
                        minimumDHGroupSize = dhSize;
                    }
                    break;
                default:
                    LOGGER.error("Unsupported key algorithm from in the certificate: {}", algorithm);
            }

        }
    }

    private void buildResultString() {
        StringBuilder sb = new StringBuilder("\n Supported cipher suites: ");
        for (ProtocolVersion pv : supportedCipherSuites.keySet()) {
            if (supportedCipherSuites.containsKey(pv)) {
                sb.append("\n  ").append(pv.toString()).append(": ")
                        .append(ciphersToString(supportedCipherSuites.get(pv)));
            }
        }
        sb.append("\n Supported ciphers: ");
        for (CipherAlgorithm ca : supportedCipherAlgorithms) {
            sb.append(ca).append(", ");
        }
        sb.append("\n Supported key exchange algorithms: ");
        for (KeyExchangeAlgorithm ke : supportedKeyExchangeAlgorithms) {
            sb.append(ke).append(", ");
        }
        sb.append("\n Supported MAC algorithms: ");
        for (MacAlgorithm ma : supportedMacAlgorithms) {
            sb.append(ma).append(", ");
        }
        sb.append("\n Supported PRF algorithms: ");
        for (PRFAlgorithm prf : supportedPRFAlgorithms) {
            sb.append(prf).append(", ");
        }
        sb.append("\n Key sizes  (0 if not provided):");
        sb.append("\n  Minimum RSA key size: ").append(minimumRSAKeySize);
        sb.append("\n  Minimum EC key size: ").append(minimumECKeySize);
        sb.append("\n  Minimum DH group size: ").append(minimumDHGroupSize);
        if (minimumDHGroupSize == 0) {
            if (supportedKeyExchangeAlgorithms.contains(KeyExchangeAlgorithm.DHE_RSA)
                    || supportedKeyExchangeAlgorithms.contains(KeyExchangeAlgorithm.DHE_DSS)
                    || supportedKeyExchangeAlgorithms.contains(KeyExchangeAlgorithm.DHE_PSK)) {
                sb.append(" (It is possible that the request timed out and the server was "
                        + "not able to generate a new ephemeral DH key on time. Try to "
                        + "increase the TLS timeout with the -tls_timeout parameter.)");
            }
        }
        result = sb.toString();
    }

    private String ciphersToString(List<CipherSuite> ciphers) {
        String output = "";
        for (CipherSuite cs : ciphers) {
            output = output + cs.name() + " ";
        }
        return output;
    }

    public HashMap<ProtocolVersion, List<CipherSuite>> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    public Set<CipherSuite> getAllSupportedCipherSuites() {
        return allSupportedCipherSuites;
    }

    public Set<KeyExchangeAlgorithm> getSupportedKeyExchangeAlgorithms() {
        return supportedKeyExchangeAlgorithms;
    }

    public Set<PRFAlgorithm> getSupportedPRFAlgorithms() {
        return supportedPRFAlgorithms;
    }

    public Set<CipherAlgorithm> getSupportedCipherAlgorithms() {
        return supportedCipherAlgorithms;
    }

    public Set<MacAlgorithm> getSupportedMacAlgorithms() {
        return supportedMacAlgorithms;
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setMacAlgorithms(supportedMacAlgorithms);
        properties.setCiphers(supportedCipherAlgorithms);
        properties.setMinimumDhGroupSize(minimumDHGroupSize);
        properties.setMinimumEcdhGroupSize(minimumECKeySize);
        properties.setMinimumRsaBits(minimumRSAKeySize);
    }

}
