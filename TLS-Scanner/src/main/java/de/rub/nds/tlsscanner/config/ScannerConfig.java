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
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScannerConfig extends TLSDelegateConfig {
    public static final String COMMAND = "scan";

    @ParametersDelegate
    private final ClientDelegate clientDelegate;

    @Parameter(names = "-language", required = true, description = "Which language the scanner should output")
    private Language language = Language.ENGLISH;

    @Parameter(names = "-threads", required = false, description = "How many threads should execute Probes")
    private int threads = 1;

    public ScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    public Language getLanguage() {
        return language;
    }

    public void setLanguage(Language language) {
        this.language = language;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

}
