/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.transport.TransportHandler;

/**
 * TODO fill this function with tls 1.2 specific data
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TLS12WorkflowExecutor extends WorkflowExecutor {

    public TLS12WorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	super(transportHandler, tlsContext);
    }

}
