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

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @param <ProtocolMessage>
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
	ProtocolMessageHandler<ProtocolMessage> {

    public HandshakeMessageHandler(TlsContext tlsContext) {
	super(tlsContext);
    }

    /**
     * Implementation hook used after the prepareMessageAction: the content of
     * the parsed protocol message is parsed and the digest value is updated
     */
    @Override
    protected void afterPrepareMessageAction() {
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	tlsContext.getDigest().update(pm);
    }

    /**
     * Implementation hook used after the parseMessageAction: the content of the
     * parsed protocol message is parsed and the digest value is updated
     */
    @Override
    protected void afterParseMessageAction() {
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	tlsContext.getDigest().update(pm);
    }

}
