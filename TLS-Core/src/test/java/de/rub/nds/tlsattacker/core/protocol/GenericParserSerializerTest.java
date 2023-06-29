/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import java.util.Random;

public class GenericParserSerializerTest {

    protected ProtocolMessage getRandomMessage(Random r) {
        switch (r.nextInt(20)) {
            case 0:
                return new AlertMessage();
            case 1:
                return new ApplicationMessage();
            case 2:
                return new CertificateMessage();
            case 3:
                return new CertificateRequestMessage();
            case 4:
                return new CertificateVerifyMessage();
            case 5:
                return new ChangeCipherSpecMessage();
            case 6:
                return new ClientHelloMessage();
            case 7:
                return new DHClientKeyExchangeMessage();
            case 8:
                return new DHEServerKeyExchangeMessage();
            case 9:
                return new ECDHClientKeyExchangeMessage();
            case 10:
                return new ECDHEServerKeyExchangeMessage();
            case 11:
                return new FinishedMessage();
            case 12:
                return new HeartbeatMessage();
            case 13:
                return new HelloRequestMessage();
            case 14:
                return new HelloVerifyRequestMessage();
            case 15:
                return new RSAClientKeyExchangeMessage();
            case 16:
                return new ServerHelloDoneMessage();
            case 17:
                return new ServerHelloMessage();
            case 18:
                return new UnknownHandshakeMessage();
            case 19:
                return new UnknownMessage();
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }
}
