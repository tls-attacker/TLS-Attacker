/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<ECDHEServerKeyExchangeMessage> {

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ECDHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new ECDHEServerKeyExchangeParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ECDHEServerKeyExchangePreparator getPreparator(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangePreparator(tlsContext, message);
    }

    @Override
    public ECDHEServerKeyExchangeSerializer getSerializer(ECDHEServerKeyExchangeMessage message) {
        return new ECDHEServerKeyExchangeSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(ECDHEServerKeyExchangeMessage message) {
        adjustECParameter(message);
        if (message.getComputations() != null) {
            ECPrivateKeyParameters privEcParams = new ECPrivateKeyParameters(message.getComputations().getPrivateKey()
                    .getValue(), tlsContext.getServerEcPublicKeyParameters().getParameters());
            tlsContext.setServerEcPrivateKeyParameters(privEcParams);
        }
    }

    private void adjustECParameter(ECDHEServerKeyExchangeMessage message) {

        byte[] ecParams = ArrayConverter.concatenate(new byte[] { message.getCurveType().getValue() }, message
                .getNamedCurve().getValue(), ArrayConverter.intToBytes(message.getSerializedPublicKeyLength()
                .getValue(), 1), message.getSerializedPublicKey().getValue());
        InputStream is = new ByteArrayInputStream(ecParams);
        ECPublicKeyParameters publicKeyParameters = null;
        try {
            publicKeyParameters = ECCUtilsBCWrapper.readECParametersWithPublicKey(is);
        } catch (TlsFatalAlert alert) {
            throw new AdjustmentException("Problematic EC parameters, we dont support these yet", alert);
        } catch (IOException ex) {
            throw new AdjustmentException("EC public key parsing failed", ex);
        }
        tlsContext.setServerECPublicKeyParameters(publicKeyParameters);
    }
}
