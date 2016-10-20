/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the IsGoodRule
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class IsGoodRuleConfig extends RuleConfig {

    /**
     *
     */
    private String outputFileGraph = "good.graph";

    /**
     *
     */
    public IsGoodRuleConfig() {
	super("good/");
    }

    /**
     *
     * @return
     */
    public String getOutputFileGraph() {
	return outputFileGraph;
    }

    /**
     *
     * @param outputFileGraph
     */
    public void setOutputFileGraph(String outputFileGraph) {
	this.outputFileGraph = outputFileGraph;
    }

}
