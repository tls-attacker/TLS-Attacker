/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<DHEServerKeyExchangeMessage> {

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
    public DHEServerKeyExchangeSerializer getSerializer(DHEServerKeyExchangeMessage message) {
        return new DHEServerKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(DHEServerKeyExchangeMessage message) {
        adjustServerDHParameters(message);
        if (message.getComputations() != null) {
            adjustServerDHPrivateParameters(message);
        }
    }

    /**
     * TODO Preparators should never change Context fields
     *
     * @param context
     */
    private void adjustServerDHPrivateParameters(DHEServerKeyExchangeMessage message) {
        tlsContext.setServerDhPrivateKeyParameters(new DHPrivateKeyParameters(message.getComputations().getPrivateKey()
                .getValue(), tlsContext.getServerDHParameters().getPublicKey().getParameters()));
        LOGGER.debug("ServerDHPrivateKeyParameters: " + tlsContext.getServerDhPrivateKeyParameters());
    }

    private void adjustServerDHParameters(DHEServerKeyExchangeMessage message) {
        DHParameters parameters = new DHParameters(new BigInteger(1, message.getP().getValue()), new BigInteger(1,
                message.getG().getValue()));
        BigInteger pubkey = new BigInteger(1, message.getSerializedPublicKey().getValue());
        ServerDHParams dhParams = new ServerDHParams(new DHPublicKeyParameters(pubkey, parameters));
        tlsContext.setServerDHParameters(dhParams);
    }
}
