/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKBinderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKIdentitySerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC draft-ietf-tls-tls13-21 */
public class PreSharedKeyExtensionPreparator
        extends ExtensionPreparator<PreSharedKeyExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PreSharedKeyExtensionMessage msg;
    private ClientHelloMessage clientHello;

    public PreSharedKeyExtensionPreparator(Chooser chooser, PreSharedKeyExtensionMessage message) {
        super(chooser, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PreSharedKeyExtensionMessage");
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            msg.getEntries(chooser);
            prepareLists();
            prepareIdentityListBytes();
            prepareBinderListBytes();
        } else {
            prepareSelectedIdentity();
        }
    }

    private void prepareLists() {
        if (msg.getIdentities() != null) {
            for (PSKIdentity pskIdentity : msg.getIdentities()) {
                new PSKIdentityPreparator(chooser, pskIdentity).prepare();
            }
        }
        if (msg.getBinders() != null) {
            for (PSKBinder pskBinder : msg.getBinders()) {
                new PSKBinderPreparator(chooser, pskBinder).prepare();
            }
        }
    }

    private void prepareSelectedIdentity() {
        LOGGER.debug("Preparing selected identity");
        msg.setSelectedIdentity(chooser.getContext().getTlsContext().getSelectedIdentityIndex());
    }

    private void prepareIdentityListBytes() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        if (msg.getIdentities() != null) {
            for (PSKIdentity pskIdentity : msg.getIdentities()) {
                PSKIdentitySerializer serializer = new PSKIdentitySerializer(pskIdentity);
                try {
                    outputStream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write byte[] from PSKIdentity", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK available, setting empty identity list");
        }
        msg.setIdentityListBytes(outputStream.toByteArray());
        msg.setIdentityListLength(msg.getIdentityListBytes().getValue().length);
    }

    private void prepareBinderListBytes() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        if (msg.getBinders() != null) {
            for (PSKBinder pskBinder : msg.getBinders()) {
                PSKBinderSerializer serializer = new PSKBinderSerializer(pskBinder);
                try {
                    outputStream.write(serializer.serialize());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write byte[] from PSKIdentity", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK available, setting empty binder list");
        }
        msg.setBinderListBytes(outputStream.toByteArray());
        msg.setBinderListLength(msg.getBinderListBytes().getValue().length);
    }

    @Override
    public void afterPrepareExtensionContent() {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            prepareActualBinders();
        }
    }

    private void prepareActualBinders() {
        LOGGER.debug("Preparing binder values to replace dummy bytes");
        ClientHelloSerializer clientHelloSerializer =
                new ClientHelloSerializer(clientHello, chooser.getSelectedProtocolVersion());
        byte[] clientHelloBytes = clientHelloSerializer.serialize();
        byte[] relevantBytes = getRelevantBytes(clientHelloBytes);
        calculateBinders(relevantBytes, msg);
        prepareBinderListBytes(); // Re-write list using actual values
    }

    private byte[] getRelevantBytes(byte[] clientHelloBytes) {
        int remainingBytes = clientHelloBytes.length - ExtensionByteLength.PSK_BINDER_LIST_LENGTH;
        if (msg.getBinders() != null) {
            for (PSKBinder pskBinder : msg.getBinders()) {
                remainingBytes =
                        remainingBytes
                                - ExtensionByteLength.PSK_BINDER_LENGTH
                                - pskBinder.getBinderEntryLength().getValue();
            }
        }
        if (remainingBytes > 0) {
            byte[] relevantBytes = new byte[remainingBytes];

            System.arraycopy(
                    clientHelloBytes,
                    0,
                    relevantBytes,
                    0,
                    Math.min(remainingBytes, clientHelloBytes.length));

            LOGGER.debug("Relevant Bytes: {}", relevantBytes);
            return relevantBytes;
        } else {
            // This can happen if the client hello degenerates
            return new byte[0];
        }
    }

    private void calculateBinders(byte[] relevantBytes, PreSharedKeyExtensionMessage msg) {
        TlsContext tlsContext = chooser.getContext().getTlsContext();
        List<PskSet> pskSets = chooser.getPskSets();
        if (msg.getBinders() != null) {
            LOGGER.debug("Calculating Binders");
            for (int x = 0; x < msg.getBinders().size(); x++) {
                try {
                    if (pskSets.size() > x) {
                        HKDFAlgorithm hkdfAlgorithm =
                                AlgorithmResolver.getHKDFAlgorithm(pskSets.get(x).getCipherSuite());
                        Mac mac = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName());
                        DigestAlgorithm digestAlgo =
                                AlgorithmResolver.getDigestAlgorithm(
                                        ProtocolVersion.TLS13, pskSets.get(x).getCipherSuite());

                        byte[] psk = pskSets.get(x).getPreSharedKey();
                        byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
                        byte[] binderKey =
                                HKDFunction.deriveSecret(
                                        hkdfAlgorithm,
                                        digestAlgo.getJavaName(),
                                        earlySecret,
                                        HKDFunction.BINDER_KEY_RES,
                                        ArrayConverter.hexStringToByteArray(""));
                        byte[] binderFinKey =
                                HKDFunction.expandLabel(
                                        hkdfAlgorithm,
                                        binderKey,
                                        HKDFunction.FINISHED,
                                        new byte[0],
                                        mac.getMacLength());

                        tlsContext.getDigest().setRawBytes(relevantBytes);
                        SecretKeySpec keySpec = new SecretKeySpec(binderFinKey, mac.getAlgorithm());
                        mac.init(keySpec);
                        mac.update(
                                tlsContext
                                        .getDigest()
                                        .digest(
                                                ProtocolVersion.TLS13,
                                                pskSets.get(x).getCipherSuite()));
                        byte[] binderVal = mac.doFinal();
                        tlsContext.getDigest().setRawBytes(new byte[0]);

                        LOGGER.debug("Using PSK: {}", psk);
                        LOGGER.debug("Calculated Binder: {}", binderVal);

                        msg.getBinders().get(x).setBinderEntry(binderVal);
                        // First entry = PSK for early Data
                        if (x == 0) {
                            tlsContext.setEarlyDataPsk(psk);
                        }
                    } else {
                        LOGGER.warn("Skipping BinderCalculation as Config has not enough PSK sets");
                    }
                } catch (NoSuchAlgorithmException | InvalidKeyException | CryptoException ex) {
                    throw new PreparationException("Could not calculate Binders", ex);
                }
            }
        } else {
            LOGGER.debug("No PSK dummy binders set, skipping binder computation");
        }
    }

    /**
     * @return the clientHello
     */
    public ClientHelloMessage getClientHello() {
        return clientHello;
    }

    /**
     * @param clientHello the clientHello to set
     */
    public void setClientHello(ClientHelloMessage clientHello) {
        this.clientHello = clientHello;
    }
}
