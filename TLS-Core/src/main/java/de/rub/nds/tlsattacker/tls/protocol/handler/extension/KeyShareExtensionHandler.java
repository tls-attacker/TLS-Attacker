/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.crypto.HKDFunction;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsDHUtils;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    public KeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public KeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new KeyShareExtensionParser(pointer, message, context.getConfig().getConnectionEnd());
    }

    @Override
    public KeyShareExtensionPreparator getPreparator(KeyShareExtensionMessage message) {
        return new KeyShareExtensionPreparator(context, message);
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(KeyShareExtensionMessage message) {
        return new KeyShareExtensionSerializer(message, context.getConfig().getConnectionEnd());
    }

    @Override
    public void adjustTLSContext(KeyShareExtensionMessage message) {
        List<KSEntry> ksEntryList = new LinkedList<>();
        for (KeySharePair pair : message.getKeyShareList()) {
            NamedCurve type = NamedCurve.getNamedCurve(pair.getKeyShareType().getValue());
            if (type != null) {
                ksEntryList.add(new KSEntry(type, pair.getKeyShare().getValue()));
            } else {
                LOGGER.warn("Unknown KS Type:" + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
            }
        }
        if (context.getConfig().getConnectionEnd() == ConnectionEnd.SERVER) {
            // The server has only one key
            context.setServerKSEntry(ksEntryList.get(0));
            adjustHandshakeTrafficSecrets();
        } else {
            context.setClientKSEntryList(ksEntryList);
        }
    }

    private void adjustHandshakeTrafficSecrets() {
        MacAlgorithm macAlg = AlgorithmResolver.getHKDFAlgorithm(context.getSelectedCipherSuite()).getMacAlgorithm();
        // PSK = null
        byte[] earlySecret = HKDFunction.extract(macAlg.getJavaName(), new byte[] {}, new byte[32]);
        byte[] saltHandshakeSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), earlySecret, HKDFunction.DERIVED,
                new byte[] {});
        byte[] sharedSecret;
        if (context.getServerKSEntry().getGroup() == NamedCurve.FFDHE2048) {
            sharedSecret = computeSharedSecretDH();
        } else {
            throw new PreparationException("Support only the key exchange group FFDHE2048");
        }
        byte[] handshakeSecret = HKDFunction.extract(macAlg.getJavaName(), saltHandshakeSecret, sharedSecret);
        // TODO with new TLS Digset
        byte[] clientHandshakeTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), handshakeSecret,
                HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
        context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
        LOGGER.debug("Set clientHandshakeTrafficSecret in Context to "+ ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret));
        byte[] serverHandshakeTrafficSecret = HKDFunction.deriveSecret(macAlg.getJavaName(), handshakeSecret,
                HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
        context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
        LOGGER.debug("Set serverHandshakeTrafficSecret in Context to "+ ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret));
    }

    public byte[] computeSharedSecretDH() {
        KSEntry serverKeySahre = context.getServerKSEntry();
        DHParameters dhParams = new DHParameters(new BigInteger(1, context.getConfig().getFixedDHModulus()),
                new BigInteger(1, context.getConfig().getFixedDHg()));
        DHPrivateKeyParameters dhPrivateClient = new DHPrivateKeyParameters(new BigInteger(1, context.getConfig().getKeyShareExponent()), dhParams);
        DHPublicKeyParameters dhPublicServer = new DHPublicKeyParameters(new BigInteger(1, serverKeySahre.getSerializedPublicKey()), dhParams);
        try {
            byte[] sharedSecret = TlsDHUtils.calculateDHBasicAgreement(dhPublicServer, dhPrivateClient);
            if (sharedSecret.length != context.getConfig().getFixedDHModulus().length) {
                return ArrayConverter.bigIntegerToNullPaddedByteArray(new BigInteger(1, sharedSecret), context.getConfig().getFixedDHModulus().length);
            } else {
                return sharedSecret;
            }
        } catch (IllegalArgumentException e) {
            throw new PreparationException("Could not calculate shared secret");
        }
    }

}
