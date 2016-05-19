/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.config;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class StartupCommandsHolder {

    private String serverCommand;

    private int serverPort;

    private String workflowFolder;

    private String modifiedVariableTypes;

    private String outputFolder;

    @XmlElementWrapper(name = "startupCommandsList")
    @XmlElements(value = { @XmlElement(type = StartupCommand.class) })
    private List<StartupCommand> startupCommands;

    public List<StartupCommand> getStartupCommands() {
	return startupCommands;
    }

    public void setStartupCommands(List<StartupCommand> startupCommands) {
	this.startupCommands = startupCommands;
    }

    public String getServerCommand() {
	return serverCommand;
    }

    public void setServerCommand(String serverCommand) {
	this.serverCommand = serverCommand;
    }

    public int getServerPort() {
	return serverPort;
    }

    public void setServerPort(int serverPort) {
	this.serverPort = serverPort;
    }

    public String getWorkflowFolder() {
	return workflowFolder;
    }

    public void setWorkflowFolder(String workflowFolder) {
	this.workflowFolder = workflowFolder;
    }

    public String getModifiedVariableTypes() {
	return modifiedVariableTypes;
    }

    public void setModifiedVariableTypes(String modifiedVariableTypes) {
	this.modifiedVariableTypes = modifiedVariableTypes;
    }

    public String getOutputFolder() {
	return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }
}
