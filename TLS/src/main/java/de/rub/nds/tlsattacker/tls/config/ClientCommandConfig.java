/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientCommandConfig extends CommandConfig {

    public static final String COMMAND = "client";

    @Parameter(names = "-connect", description = "who to connect to")
    protected String connect = "localhost:4433";

    @Parameter(names = "-workflow_trace_type", description = "Type of the workflow trace (FULL or HANDSHAKE)")
    protected WorkflowTraceType workflowTraceType = WorkflowTraceType.FULL;

    public String getConnect() {
	return connect;
    }

    public void setConnect(String connect) {
	this.connect = connect;
    }

    public WorkflowTraceType getWorkflowTraceType() {
	return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
	this.workflowTraceType = workflowTraceType;
    }
}
