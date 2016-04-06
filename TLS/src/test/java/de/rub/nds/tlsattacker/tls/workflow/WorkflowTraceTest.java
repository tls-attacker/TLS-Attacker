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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class WorkflowTraceTest {

    WorkflowTrace trace;

    public WorkflowTraceTest() {
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initializeGeneralConfig(new GeneralConfig());
	ClientCommandConfig ccc = new ClientCommandConfig();
	TlsContext tlsContext = configHandler.initializeTlsContext(ccc);
	trace = tlsContext.getWorkflowTrace();
    }

    @Test
    public void testDeepCopy() {
	WorkflowTrace copy = (WorkflowTrace) UnoptimizedDeepCopy.copy(trace);
	assertEquals("The number of messages in both traces has to be equal", trace.getProtocolMessages().size(), copy
		.getProtocolMessages().size());
    }

}
