/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.probe.certificate.CertificateJudger;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReportGenerator;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateProbe extends TLSProbe {

    private static final Logger LOGGER = LogManager.getLogger(CertificateProbe.class);

    public CertificateProbe(ScannerConfig config) {
        super("Certificate Probe", config);
    }

    @Override
    public ProbeResult call() {
        TlsConfig tlsConfig = getConfig().createConfig();
        Certificate serverCert = CertificateFetcher.fetchServerCertificate(tlsConfig);
        List<TLSCheck> checkList = new LinkedList<>();
        List<ResultValue> resultList = new LinkedList<>();
        List<CertificateReport> reportList = CertificateReportGenerator.generateReports(serverCert);
        CertificateReport report = CertificateReportGenerator.generateReport(serverCert.getCertificateAt(0));
        CertificateJudger judger = new CertificateJudger(serverCert.getCertificateAt(0), getConfig(), report);
        checkList.addAll(judger.getChecks());
        return new ProbeResult(getProbeName(), resultList, checkList);
    }
}
