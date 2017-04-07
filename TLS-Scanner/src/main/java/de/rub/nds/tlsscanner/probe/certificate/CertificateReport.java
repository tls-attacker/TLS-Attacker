/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import java.security.PublicKey;
import java.util.Date;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public interface CertificateReport {

    public String getSubject();

    public String getCommonNames();

    public String getAlternativenames();

    public Date getValidFrom();

    public Date getValidTo();

    public PublicKey getPublicKey();

    public Boolean getWeakDebianKey();

    public String getIssuer();

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();

    public Boolean getExtendedValidation();

    public Boolean getCertificateTransparency();

    public Boolean getOcspMustStaple();

    public Boolean getCrlSupported();

    public Boolean getOcspSupported();

    public Boolean getRevoked();

    public Boolean getDnsCAA();

    public Boolean getTrusted();

}
