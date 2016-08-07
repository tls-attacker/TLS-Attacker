/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config.Analyzer;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeTimeRuleConfig extends RuleConfig {
    private String outputFile = "timing.results";

    public String getOutputFile() {
	return outputFile;
    }

    public void setOutputFile(String outputFile) {
	this.outputFile = outputFile;
    }

}
