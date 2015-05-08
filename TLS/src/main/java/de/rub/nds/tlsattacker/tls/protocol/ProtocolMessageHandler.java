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
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Message>
 */
public abstract class ProtocolMessageHandler<Message extends ProtocolMessage> {

    /**
     * tls context
     */
    protected final TlsContext tlsContext;

    /**
     * handled protocol message
     */
    protected Message protocolMessage;

    /**
     * type of the protocol message class
     */
    protected Class<? extends ProtocolMessage> correctProtocolMessageClass;

    /**
     * 
     * @param tlsContext
     */
    public ProtocolMessageHandler(TlsContext tlsContext) {
	// ProtocolController protocolController =
	// ProtocolController.getInstance();
	this.tlsContext = tlsContext;
	if (tlsContext == null) {
	    throw new ConfigurationException("TLS Context is not configured yet");
	}
    }

    /**
     * Prepare message for sending. This method invokes before and after method
     * hooks.
     * 
     * @return message in bytes
     */
    public byte[] prepareMessage() {
	beforePrepareMessageAction();
	byte[] ret = prepareMessageAction();
	afterPrepareMessageAction();
	return ret;
    }

    /**
     * Parse incoming message bytes and return a pointer to the last processed
     * byte. This pointer is then used by further protocol message handler. This
     * method invokes before and after method hooks.
     * 
     * @param message
     * @param pointer
     * @return
     */
    public int parseMessage(byte[] message, int pointer) {
	beforeParseMessageAction();
	int ret = parseMessageAction(message, pointer);
	afterParseMessageAction();
	return ret;
    }

    /**
     * Prepare message for sending
     * 
     * @return message in bytes
     */
    protected abstract byte[] prepareMessageAction();

    /**
     * Parse incoming message bytes and return a pointer to the last processed
     * byte. This pointer is then used by further protocol message handler.
     * 
     * @param message
     * @param pointer
     * @return
     */
    protected abstract int parseMessageAction(byte[] message, int pointer);

    /**
     * Implementation hook, which allows the handlers to invoke specific methods
     * before the prepareMessageAction is executed
     */
    protected void beforePrepareMessageAction() {
    }

    /**
     * Implementation hook, which allows the handlers to invoke specific methods
     * after the prepareMessageAction is executed
     */
    protected void afterPrepareMessageAction() {
    }

    /**
     * Implementation hook, which allows the handlers to invoke specific methods
     * before the parseMessageAction is executed
     */
    protected void beforeParseMessageAction() {
    }

    /**
     * Implementation hook, which allows the handlers to invoke specific methods
     * after the parseMessageAction is executed
     */
    protected void afterParseMessageAction() {
    }

    /**
     * Checks the protocol message
     * 
     * @param protocolMessage
     * @return
     */
    public boolean isCorrectProtocolMessage(ProtocolMessage protocolMessage) {
	if (protocolMessage == null) {
	    return false;
	} else {
	    return protocolMessage.getClass().equals(correctProtocolMessageClass);
	}

    }

    /**
     * This method is used to initialize new protocol message in a case we are
     * handling a dynamic message exchange or an unexpected message is received
     * and we have to initialize it.
     */
    public void initializeProtocolMessage() {

	try {
	    Constructor c = correctProtocolMessageClass.getConstructor();
	    Message pm = (Message) c.newInstance();
	    this.protocolMessage = pm;
	} catch (SecurityException | IllegalAccessException | IllegalArgumentException | InstantiationException
		| InvocationTargetException | NoSuchMethodException ex) {
	    throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	}
    }

    /**
     * @return newly initialized protocol message used by this handler
     */
    public Message getProtocolMessage() {
	return this.protocolMessage;
    }

    /**
     * @param protocolMessage
     */
    public void setProtocolMessage(Message protocolMessage) {
	this.protocolMessage = protocolMessage;
    }
}
