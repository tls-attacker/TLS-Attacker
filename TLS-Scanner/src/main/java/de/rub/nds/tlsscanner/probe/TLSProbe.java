/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSProbe implements Callable<ProbeResult> {

    protected static final Logger LOGGER = LogManager.getLogger("Probe");

    private ScannerConfig config;
    private String probeName;

    public TLSProbe(String testName, ScannerConfig config) {
        this.probeName = testName;
        this.config = config;
    }

    public ScannerConfig getConfig() {
        return config;
    }

    public String getProbeName() {
        return probeName;
    }

    @Override
    public abstract ProbeResult call();
}
