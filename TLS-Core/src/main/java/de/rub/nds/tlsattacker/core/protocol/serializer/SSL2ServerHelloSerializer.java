/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ssl.SSLByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ServerHelloSerializer extends ProtocolMessageSerializer {

    private final SSL2ServerHelloMessage message;

    public SSL2ServerHelloSerializer(SSL2ServerHelloMessage message, TlsContext tlsContext) {
        super(message, tlsContext.getSelectedProtocolVersion());
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        appendInt(message.getMessageLength().getValue(), SSLByteLength.LENGTH);
        appendByte(message.getType().getValue());
        appendByte(message.getSessionIdHit().getValue());
        appendByte(message.getCertificateType().getValue());
        appendBytes(message.getProtocolVersion().getValue());
        appendInt(message.getCertificateLength().getValue(), SSLByteLength.CERTIFICATE_LENGTH);
        appendInt(message.getCiphersuitesLength().getValue(), SSLByteLength.CIPHERSUITE_LENGTH);
        appendInt(message.getSessionIDLength().getValue(), SSLByteLength.SESSIONID_LENGTH);
        appendBytes(message.getCertificate().getValue());
        appendBytes(message.getCipherSuites().getValue());
        appendBytes(message.getSessionID().getValue());
        return getAlreadySerialized();
    }

}
