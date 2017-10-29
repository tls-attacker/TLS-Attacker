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
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.PSKECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PSKECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PSKECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PSKECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

/**
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKECDHEServerKeyExchangeHandler extends ServerKeyExchangeHandler<PSKECDHEServerKeyExchangeMessage> {

    public PSKECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public PSKECDHEServerKeyExchangeParser getParser(byte[] message, int pointer) {
        return new PSKECDHEServerKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public PSKECDHEServerKeyExchangePreparator getPreparator(PSKECDHEServerKeyExchangeMessage message) {
        return new PSKECDHEServerKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public PSKECDHEServerKeyExchangeSerializer getSerializer(PSKECDHEServerKeyExchangeMessage message) {
        return new PSKECDHEServerKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(PSKECDHEServerKeyExchangeMessage message) {
        adjustECParameter(message);
        if (message.getComputations() != null) {
            tlsContext.setServerEcPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }

    private void adjustECParameter(PSKECDHEServerKeyExchangeMessage message) {
        tlsContext.setSelectedCurve(NamedCurve.getNamedCurve(message.getNamedCurve().getValue()));
        // TODO avoid BC tool
        byte[] ecParams = ArrayConverter.concatenate(new byte[] { message.getCurveType().getValue() }, message
                .getNamedCurve().getValue(), ArrayConverter.intToBytes(message.getPublicKeyLength().getValue(), 1),
                message.getPublicKey().getValue());
        InputStream is = new ByteArrayInputStream(ecParams);
        ECPublicKeyParameters publicKeyParameters = null;
        try {
            publicKeyParameters = ECCUtilsBCWrapper.readECParametersWithPublicKey(is);
        } catch (TlsFatalAlert alert) {
            throw new AdjustmentException("Problematic EC parameters, we dont support these yet", alert);
        } catch (IOException ex) {
            throw new AdjustmentException("EC public key parsing failed", ex);
        }
        CustomECPoint publicKey = new CustomECPoint(publicKeyParameters.getQ().getRawXCoord().toBigInteger(),
                publicKeyParameters.getQ().getRawYCoord().toBigInteger());
        tlsContext.setServerEcPublicKey(publicKey);
    }
}
