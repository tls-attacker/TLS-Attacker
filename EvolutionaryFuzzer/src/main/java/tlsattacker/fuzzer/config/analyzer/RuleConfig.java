/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.analyzer;

/**
 * The super class for all Rule configuration classes
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class RuleConfig {

    /**
     *
     */
    protected boolean active = true;

    /**
     *
     */
    protected String outputFolderName;

    /**
     *
     * @param outputFolderName
     */
    public RuleConfig(String outputFolderName) {
	this.outputFolderName = outputFolderName;
    }

    /**
     *
     * @return
     */
    public boolean isActive() {
	return active;
    }

    /**
     *
     * @param active
     */
    public void setActive(boolean active) {
	this.active = active;
    }

    /**
     *
     * @return
     */
    public String getOutputFolder() {
	return outputFolderName;
    }

    /**
     *
     * @param outputFolder
     */
    public void setOutputFolder(String outputFolder) {
	this.outputFolderName = outputFolder;
    }

}
