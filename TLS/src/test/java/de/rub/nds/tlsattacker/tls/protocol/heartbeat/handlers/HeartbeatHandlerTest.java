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
package de.rub.nds.tlsattacker.tls.protocol.heartbeat.handlers;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class HeartbeatHandlerTest {
    
    HeartbeatHandler heartbeatHandler;
    
    public HeartbeatHandlerTest() {
        TlsContext context = new TlsContext();        
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setProtocolVersion(ProtocolVersion.TLS12);
        heartbeatHandler = new HeartbeatHandler(context);
    }

    /**
     * Test of prepareMessageAction method, of class HeartbeatHandler.
     */
    @Test
    public void testPrepareMessageAction() {
        heartbeatHandler.initializeProtocolMessage();
        byte[] result = heartbeatHandler.prepareMessageAction();
        
        //Check maximum message length ("MUST NOT exceed 2^14")
        assertTrue(result.length <= 16384);
        //Check minimum message length
        assertTrue(result.length >= 19);
        //Make sure message is a request
        assertEquals(result[0], 0x01);
        //Check size of payload_length
        int payload_length = result[1];
        payload_length = (payload_length << 8) ^ result[2];
        assertTrue(payload_length < 16365);
        //Make sure message is long enough according to it's payload length
        assertTrue(result.length >= (payload_length + 19));
    }

    /**
     * Test of parseMessageAction method, of class HeartbeatHandler.
     */
    @Test
    public void testParseMessageAction() {
    }
    
}
