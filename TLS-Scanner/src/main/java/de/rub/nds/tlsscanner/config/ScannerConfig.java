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
package de.rub.nds.tlsscanner.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsscanner.report.check.CheckConfigCache;
import java.io.File;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScannerConfig extends Delegate {

    @Parameter(names = "-language_path", required = true, description = "Which language configuration folder to use")
    private String resultFilePath = "../resources/scanner/config_en/";

    public String getResultFilePath() {
        return resultFilePath;
    }

    public void setResultFilePath(String resultFilePath) {
        this.resultFilePath = resultFilePath;
    }

    public ScannerConfig() {
    }

    @Override
    public void applyDelegate(TlsConfig config) throws ConfigurationException {
        if (resultFilePath != null) {
            CheckConfigCache.getInstance().setPathToConfig(new File(resultFilePath));
        }
    }
}
