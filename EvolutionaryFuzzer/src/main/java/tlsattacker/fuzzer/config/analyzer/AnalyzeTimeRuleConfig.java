/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the analyze time rule
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class AnalyzeTimeRuleConfig extends RuleConfig {

    /**
     * The file to which the execution times of Testvectors should be serialized to
     */
    private String outputFile = "timing.results";

    public AnalyzeTimeRuleConfig() {
	super(null);
    }

    public String getOutputFile() {
	return outputFile;
    }

    public void setOutputFile(String outputFile) {
	this.outputFile = outputFile;
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRuleConfig.class.getName());

}
