/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A configuration class for the IsGoodRule
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class IsGoodRuleConfig extends RuleConfig {

    /**
     * The name of the file to which the graph should be saved to
     */
    private String outputFileGraph = "good.graph";

    public IsGoodRuleConfig() {
        super("good/");
    }

    public String getOutputFileGraph() {
        return outputFileGraph;
    }

    public void setOutputFileGraph(String outputFileGraph) {
        this.outputFileGraph = outputFileGraph;
    }

    private static final Logger LOG = Logger.getLogger(IsGoodRuleConfig.class.getName());

}
