/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.CipherSuiteConverter;
import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzerModuleDelegate extends Delegate {

    /**
     * The agent that should be used
     */
    @Parameter(names = "-analyzer", description = "The Analyzer that should be used to analyze the Results (Default: rule). Possible: rule")
    protected String analyzer = "rule";

    public AnalyzerModuleDelegate() {
    }

    public String getAnalyzer() {
        return analyzer;
    }

    public void setAnalyzer(String analyzer) {
        this.analyzer = analyzer;
    }
    
    @Override
    public void applyDelegate(TlsConfig config) {
    }

}
