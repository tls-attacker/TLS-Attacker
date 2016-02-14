/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
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
}
