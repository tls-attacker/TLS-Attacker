/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.probe.certificate.CertificateJudger;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateProbe extends TLSProbe {

    private static final Logger LOGGER = LogManager.getLogger(CertificateProbe.class);

    public CertificateProbe(String serverHost) {
        super("Certificate", serverHost);
    }

    @Override
    public ProbeResult call() {

        TlsConfig config = new TlsConfig();
        config.setHost(this.getServerHost());
        X509CertificateObject serverCert = CertificateFetcher.fetchServerCertificate(config);
        CertificateJudger judger = new CertificateJudger();
        List<ConfigurationFlaw> flawList = judger.getFlaws(serverCert, getServerHost());
        List<ResultValue> resultList = judger.getResults(serverCert, getServerHost());
        return new ProbeResult(getProbeName(), resultList, flawList);

    }

}
