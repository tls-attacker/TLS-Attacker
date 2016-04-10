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
package de.rub.nds.tlsattacker.attacks.ths.oldTHSwithThreads;

import de.rub.nds.tlsattacker.attacks.ths.oldTHSwithThreads.TripleHandshakeWorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the a workflow in a Thread
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeAttackWorflowThread implements Runnable {

    public static Logger LOGGER = LogManager.getLogger(TripleHandshakeAttackWorflowThread.class);

    TripleHandshakeWorkflowExecutor workflowExecutor;
    TransportHandler transportHandler;

    public TripleHandshakeAttackWorflowThread(TripleHandshakeWorkflowExecutor workflowExecutor,
	    TransportHandler transportHandler) {
	this.workflowExecutor = workflowExecutor;
	this.transportHandler = transportHandler;
    }

    @Override
    public void run() {
	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();
    }

}
