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
     * If the rule is active
     */
    protected boolean active = true;

    /**
     * The name of the folder to which data should be outputted
     */
    protected String outputFolderName;

    public RuleConfig(String outputFolderName) {
        this.outputFolderName = outputFolderName;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getOutputFolder() {
        return outputFolderName;
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolderName = outputFolder;
    }

}
