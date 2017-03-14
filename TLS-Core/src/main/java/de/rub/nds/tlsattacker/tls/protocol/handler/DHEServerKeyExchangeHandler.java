/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.util.BigIntegers;
import sun.security.rsa.RSAPublicKeyImpl;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new DHEServerKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public DHEServerKeyExchangePreparator getPreparator(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(DHEServerKeyExchangeMessage message) {
        adjustServerDHParameters(message);
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
    }

    private void adjustServerDHParameters(DHEServerKeyExchangeMessage message) {
        DHParameters parameters = new DHParameters(message.getP().getValue(), message.getG().getValue());
        BigInteger pubkey = new BigInteger(1, message.getSerializedPublicKey().getValue());
        ServerDHParams dhParams = new ServerDHParams(new DHPublicKeyParameters(pubkey, parameters));
        tlsContext.setServerDHParameters(dhParams);
        // tlsContext.setServerPublicKey();

    }
}
