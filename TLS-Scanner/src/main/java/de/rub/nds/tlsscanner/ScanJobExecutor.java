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

import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.TLSProbe;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScanJobExecutor {
    private ExecutorService executor;

    public ScanJobExecutor(int threadCount) {
        executor = Executors.newFixedThreadPool(1);
    }

    public SiteReport execute(ScannerConfig config, ScanJob scanJob) {
        List<Future<ProbeResult>> futureResults = new LinkedList<>();
        for (TLSProbe probe : scanJob.getProbeList()) {
            futureResults.add(executor.submit(probe));
        }
        List<ProbeResult> resultList = new LinkedList<>();
        for (Future<ProbeResult> probeResult : futureResults) {
            try {
                resultList.add(probeResult.get());
            } catch (InterruptedException | ExecutionException ex) {
                Logger.getLogger(ScanJobExecutor.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        executor.shutdown();
        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegate(ClientDelegate.class);
        String hostname = clientDelegate.getHost();
        return new SiteReport(hostname, resultList);
    }
}
