/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config.Analyzer;

import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FindAlertsRuleConfig extends RuleConfig {
    // List of Alert codes, if we see this alert we save the workflow trace
    private LinkedList<Integer> blackList;
    // Set of RFC Comform Alert Codes, every Code that is not in this list is
    // saved
    private Set<Byte> whitelist;
    // The Pokemon method, the Rule is advised to save one example testvector
    // for each alert message
    private boolean saveOneOfEach = true;
    // Output folder relative to the evolutionaryConfig output folder
    private String outputFolder = "alerts/";

    public FindAlertsRuleConfig() {
	this.blackList = new LinkedList<>();
	blackList.add(80);
	this.whitelist = new HashSet<>();
	// we add all AlertDescriptions TLS Attacker knows to the whitelist
	for (AlertDescription des : AlertDescription.values()) {
	    whitelist.add(des.getValue());
	}
    }

    public LinkedList<Integer> getBlackList() {
	return blackList;
    }

    public void setBlackList(LinkedList<Integer> blackList) {
	this.blackList = blackList;
    }

    public Set<Byte> getWhitelist() {
	return whitelist;
    }

    public void setWhitelist(Set<Byte> whitelist) {
	this.whitelist = whitelist;
    }

    public boolean isSaveOneOfEach() {
	return saveOneOfEach;
    }

    public void setSaveOneOfEach(boolean saveOneOfEach) {
	this.saveOneOfEach = saveOneOfEach;
    }

    public String getOutputFolder() {
	return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }

}
