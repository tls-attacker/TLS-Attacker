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
package de.rub.nds.tlsattacker.tls.exceptions;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * Invalid message type exception (thrown when unexpected TLS message appears
 * during the TLS workflow)
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidMessageTypeException extends RuntimeException {

    public InvalidMessageTypeException() {
	super();
    }

    public InvalidMessageTypeException(String message) {
	super(message);
    }

    public InvalidMessageTypeException(ProtocolMessageType protocolMessageType) {
	super("This is not a " + protocolMessageType + " message");
    }

    public InvalidMessageTypeException(HandshakeMessageType handshakeMessageType) {
	super("This is not a " + handshakeMessageType + " message");
    }
}
