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
package de.rub.nds.tlsattacker.tls.workflow;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class WorkflowContext {

    private int protocolMessagePointer;

    private boolean proceedWorkflow;

    public WorkflowContext() {
	protocolMessagePointer = 0;
	proceedWorkflow = true;
    }

    public int getProtocolMessagePointer() {
	return protocolMessagePointer;
    }

    public void setProtocolMessagePointer(int protocolMessagePointer) {
	this.protocolMessagePointer = protocolMessagePointer;
    }

    public boolean isProceedWorkflow() {
	return proceedWorkflow;
    }

    public void setProceedWorkflow(boolean proceedWorkflow) {
	this.proceedWorkflow = proceedWorkflow;
    }

    public void incrementProtocolMessagePointer() {
	protocolMessagePointer++;
    }

    public void decrementProtocolMessagePointer() {
	protocolMessagePointer--;
    }
}
