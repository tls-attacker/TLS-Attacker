/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *

 */
public class CertificateByteChooser {

    protected static final Logger LOGGER = LogManager.getLogger(CertificateByteChooser.class.getName());

    public static byte[] chooseCertificateType(Config config) {
        CipherSuite suite = config.getDefaultSelectedCipherSuite();
        byte[] rsaCert = config.getDefaultRsaCertificate();
        byte[] ecCert = config.getDefaultEcCertificate();
        byte[] dsaCert = config.getDefaultDsaCertificate();
        return chooseCertificateType(suite, rsaCert, ecCert, dsaCert);
    }

    public static byte[] chooseCertificateType(TlsContext context) {
        return chooseCertificateType(context.getChooser());
    }

    public static byte[] chooseCertificateType(Chooser chooser) {
        CipherSuite suite = chooser.getSelectedCipherSuite();
        byte[] rsaCert = chooser.getConfig().getDefaultRsaCertificate();
        byte[] ecCert = chooser.getConfig().getDefaultEcCertificate();
        byte[] dsaCert = chooser.getConfig().getDefaultDsaCertificate();
        return chooseCertificateType(suite, rsaCert, ecCert, dsaCert);
    }

    private static byte[] chooseCertificateType(CipherSuite selectedSuite, byte[] rsaCert, byte[] ecCert, byte[] dsaCert) {
        switch (AlgorithmResolver.getKeyExchangeAlgorithm(selectedSuite)) {
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
                return ecCert;
            case DHE_RSA:
            case DH_RSA:
            case ECDH_RSA:
            case ECDHE_RSA:
            case RSA:
            case SRP_SHA_RSA:
                return rsaCert;
            case DHE_DSS:
            case DH_DSS:
            case SRP_SHA_DSS:
                return dsaCert;
        }
        LOGGER.warn("Could not choose correct Certificate base on KeyExchangeAlgorithm. Selecting RSA Certificate");
        return rsaCert;
    }
}
