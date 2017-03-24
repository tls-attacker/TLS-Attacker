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
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.SignatureAndHashAlgorithmProbe;
import de.rub.nds.tlsscanner.probe.TLSProbe;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Future;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSScanner {

    private final ScanJobExecutor executor;
    private final String websiteHost;

    public TLSScanner(String websiteHost) {
        this.executor = new ScanJobExecutor(1);
        this.websiteHost = websiteHost;
    }

    public TLSScanner(ScannerConfig config) {
        this.executor = new ScanJobExecutor(1);
        this.websiteHost = config.createConfig().getHost();
    }

    public SiteReport scan() {
        List<TLSProbe> testList = new LinkedList<>();
        testList.add(new CertificateProbe(websiteHost));
        testList.add(new ProtocolVersionProbe(websiteHost));
        testList.add(new CiphersuiteProbe(websiteHost));
        testList.add(new CiphersuiteOrderProbe(websiteHost));
        // testList.add(new HeartbleedProbe(websiteHost));
        // testList.add(new NamedCurvesProbe(websiteHost));
        // testList.add(new PaddingOracleProbe(websiteHost));
        // testList.add(new SignatureAndHashAlgorithmProbe(websiteHost));
        ScanJob job = new ScanJob(testList);
        return executor.execute(websiteHost, job);
    }

}
