/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class ClientHelloHandlerTest {

    ClientHelloHandler handler;

    public ClientHelloHandlerTest() {
	handler = new ClientHelloHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class ClientHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler.initializeProtocolMessage();
        
        ClientHelloMessage message = (ClientHelloMessage) handler.getProtocolMessage(); 
        
        List<CipherSuite> cipherSuites = new ArrayList();
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        message.setSupportedCipherSuites(cipherSuites);
        
        List<CompressionMethod> compressionMethods = new ArrayList();
        compressionMethods.add(CompressionMethod.NULL);
        message.setSupportedCompressionMethods(compressionMethods);      
        
        byte[] returned = handler.prepareMessageAction();
        byte[] expected = ArrayConverter.concatenate(
                new byte[]{HandshakeMessageType.CLIENT_HELLO.getValue()},
                new byte[]{0x00, 0x00, 0x29},
                ProtocolVersion.TLS12.getValue(),
                message.getUnixTime().getValue(),
                message.getRandom().getValue(),
                new byte[]{0x00, 0x00, 0x02},
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getValue(),
                new byte[]{0x01, CompressionMethod.NULL.getValue()});
        
        assertNotNull("Confirm function didn't return 'NULL'", returned); 
        assertArrayEquals("Confirm returned message equals the expected message",
                expected, returned);
    }
}
