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
package de.rub.nds.tlsattacker.dtls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields.HandshakeMessageDtlsFields;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsHandshakeHandler {
    
    public static byte[] parseDtlsHandshakeFields(byte[] rawMessageBytes, int messageBytesOffset, HandshakeMessageDtlsFields handshakeMessageDtlsFields) {
        int auxInt = rawMessageBytes[messageBytesOffset + 4] << 8 + rawMessageBytes[messageBytesOffset + 5];
        handshakeMessageDtlsFields.setMessageSeq(auxInt);
        auxInt = rawMessageBytes[messageBytesOffset + 6] << 16 + rawMessageBytes[messageBytesOffset + 7] << 8 + rawMessageBytes[messageBytesOffset + 8];
        handshakeMessageDtlsFields.setFragmentOffset(auxInt);
        auxInt = rawMessageBytes[messageBytesOffset + 9] << 16 + rawMessageBytes[messageBytesOffset + 10] << 8 + rawMessageBytes[messageBytesOffset + 11];
        handshakeMessageDtlsFields.setFragmentLength(auxInt);
        
        auxInt = rawMessageBytes[messageBytesOffset + 1] << 16 + rawMessageBytes[messageBytesOffset + 2] << 8 + rawMessageBytes[messageBytesOffset + 3];
        byte[] output = new byte[auxInt + 4];
        
        System.arraycopy(rawMessageBytes, messageBytesOffset, output, 0, 4);
        System.arraycopy(rawMessageBytes, messageBytesOffset + 12, output, 4, auxInt);
        
        return output;
    }
    
}
