/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ec.Curve25519;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Mac;

/**
 * This handler processes the KeyShare extensions in ClientHello and ServerHello
 * messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.7
 * 
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    public KeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public KeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new KeyShareExtensionParser(pointer, message);
    }

    @Override
    public KeyShareExtensionPreparator getPreparator(KeyShareExtensionMessage message) {
        return new KeyShareExtensionPreparator(new DefaultChooser(context, context.getConfig()), message);
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(KeyShareExtensionMessage message) {
        return new KeyShareExtensionSerializer(message, context.getConfig().getConnectionEndType());
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
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            // The server has only one key
            context.setServerKSEntry(ksEntryList.get(0));
            adjustHandshakeTrafficSecrets();
        } else {
            context.setClientKSEntryList(ksEntryList);
        }
    }

    private void adjustHandshakeTrafficSecrets() {
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(context.getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        // PSK = null
        try {
            int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] earlySecret = HKDFunction.extract(hkdfAlgortihm, new byte[0], new byte[macLength]);
            byte[] saltHandshakeSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(), earlySecret,
                    HKDFunction.DERIVED, ArrayConverter.hexStringToByteArray(""));
            byte[] sharedSecret;
            if (context.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                if (context.getServerKSEntry().getGroup() == NamedCurve.ECDH_X25519) {
                    sharedSecret = computeSharedSecretECDH(context.getServerKSEntry());
                } else {
                    throw new PreparationException("Currently only the key exchange group ECDH_X25519 is supported");
                }
            } else {
                int pos = 0;
                for (KSEntry entry : context.getClientKSEntryList()) {
                    if (entry.getGroup() == NamedCurve.ECDH_X25519) {
                        pos = context.getClientKSEntryList().indexOf(entry);
                    }
                }
                if (context.getClientKSEntryList().get(pos).getGroup() == NamedCurve.ECDH_X25519) {
                    sharedSecret = computeSharedSecretECDH(context.getClientKSEntryList().get(pos));
                } else {
                    throw new PreparationException("Currently only the key exchange group ECDH_X25519 is supported");
                }
            }
            byte[] handshakeSecret = HKDFunction.extract(hkdfAlgortihm, saltHandshakeSecret, sharedSecret);
            context.setHandshakeSecret(handshakeSecret);
            LOGGER.debug("Set handshakeSecret in Context to " + ArrayConverter.bytesToHexString(handshakeSecret));
            byte[] clientHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    handshakeSecret, HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
            LOGGER.debug("Set clientHandshakeTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret));
            byte[] serverHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    handshakeSecret, HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
            LOGGER.debug("Set serverHandshakeTrafficSecret in Context to "
                    + ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * Computes the shared secret for ECDH_X25519
     * 
     * @return
     */
    private byte[] computeSharedSecretECDH(KSEntry keyShare) {
        byte[] privateKey = context.getConfig().getKeySharePrivate();
        byte[] publicKey = keyShare.getSerializedPublicKey();
        Curve25519.clamp(privateKey);
        byte[] sharedSecret = new byte[32];
        Curve25519.curve(sharedSecret, privateKey, publicKey);
        return sharedSecret;
    }

}
