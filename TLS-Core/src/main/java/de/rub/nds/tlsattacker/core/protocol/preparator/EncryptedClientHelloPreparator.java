/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeSenderContext;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedClientHelloExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloPreparator
        extends CoreClientHelloPreparator<EncryptedClientHelloMessage> {

    private final Logger LOGGER = LogManager.getLogger();

    private static final int PADDED_LENGTH = 32;

    private final EncryptedClientHelloMessage msg;

    private byte[] sessionId;

    private final EchConfig echConfig;

    private HpkeSenderContext hpkeSenderContext;

    private byte[] clientHelloInnerValue;

    public EncryptedClientHelloPreparator(Chooser chooser, EncryptedClientHelloMessage message) {
        super(chooser, message);
        msg = message;
        this.echConfig = chooser.getEchConfig();
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing EncryptedClientHelloMessage");
        prepareClientHelloInner();
        prepareEncodedClientHelloInner();
        prepareHpkeContext();
        prepareClientHelloOuterAAD();
        prepareEncryptClientHelloOuter();
        // prepare extensions and length again as we copied values between clienthellos and,
        // therefore, invalidated
        // the present length computations
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareClientHelloInner() {
        LOGGER.debug("Preparing ClientHelloInner");
        ClientHelloMessage clientHelloInner = new ClientHelloMessage(chooser.getConfig());
        clientHelloInner.getPreparator(chooser.getContext().getTlsContext()).prepare();

        // already serialize and save message bytes before the encoding process
        byte[] clientHelloInnerBytes =
                new ClientHelloSerializer(clientHelloInner, chooser.getSelectedProtocolVersion())
                        .serialize();
        clientHelloInner.setCompleteResultingMessage(clientHelloInnerBytes);
        clientHelloInner
                .getHandler(chooser.getContext().getTlsContext())
                .adjustContext(clientHelloInner);

        msg.setClientHelloInner(clientHelloInner);
    }

    private void prepareEncodedClientHelloInner() {
        LOGGER.debug("Encoding ClientHelloInner");
        ClientHelloMessage clientHelloInner = msg.getClientHelloInner();
        // construct encoded ClientHelloInner
        // TODO: add extension compression?
        // - set legacy session id to empty string but save first
        sessionId = clientHelloInner.getSessionId().getValue();
        clientHelloInner.setSessionIdLength(0);
        clientHelloInner.setSessionId(new byte[] {});

        this.clientHelloInnerValue =
                clientHelloInner
                        .getSerializer(chooser.getContext().getTlsContext())
                        .serializeHandshakeMessageContent();

        // - zero padding
        int padding = 0;
        AlpnExtensionMessage alpnExtensionMessage =
                clientHelloInner.getExtension(AlpnExtensionMessage.class);
        // pad alpn extension
        int alpnPaddingLength = 0;
        if (alpnExtensionMessage != null) {
            alpnPaddingLength = alpnExtensionMessage.getExtensionLength().getValue();
            alpnPaddingLength =
                    Math.max(
                            0,
                            chooser.getConfig().getDefaultMaxEchAlpnPadding() - alpnPaddingLength);
            padding += alpnPaddingLength;
        }
        // pad sni extension
        ServerNameIndicationExtensionMessage serverNameIndicationExtensionMessage =
                clientHelloInner.getExtension(ServerNameIndicationExtensionMessage.class);
        int sniPaddingLength = 0;
        if (serverNameIndicationExtensionMessage != null) {
            sniPaddingLength = serverNameIndicationExtensionMessage.getExtensionLength().getValue();
            sniPaddingLength =
                    Math.max(0, chooser.getEchConfig().getMaximumNameLength() - sniPaddingLength);
            padding += sniPaddingLength;
        }
        int message_size = clientHelloInnerValue.length + alpnPaddingLength + sniPaddingLength;
        // pad to a multiple of PADDED_LENGTH bytes
        padding += ((PADDED_LENGTH - 1) - ((message_size - 1) % PADDED_LENGTH));
        byte[] paddingBytes = new byte[padding];
        msg.setEncodedClientHelloInnerPadding(paddingBytes);

        LOGGER.debug(
                "Encoded ClientHello inner: "
                        + ArrayConverter.bytesToHexString(clientHelloInnerValue));
        LOGGER.debug("Padding length: " + padding);
    }

    private void prepareHpkeContext() {
        LOGGER.debug("Preparing HPKEContext");

        // log own private and public key
        LOGGER.debug(
                "ClientPrivateKey: "
                        + ArrayConverter.bytesToHexString(
                                chooser.getEchClientKeyShareEntry().getPrivateKey().toByteArray()));
        LOGGER.debug(
                "ClientPublicKey: "
                        + ArrayConverter.bytesToHexString(
                                chooser.getEchClientKeyShareEntry().getPublicKey().getValue()));

        HpkeUtil hpkeUtil =
                new HpkeUtil(
                        echConfig.getHpkeAeadFunction(),
                        echConfig.getHpkeKeyDerivationFunction(),
                        echConfig.getKem());
        // RFC 9180, Section 6.1
        byte[] info =
                ArrayConverter.concatenate(
                        "tls ech".getBytes(),
                        new byte[] {0x00},
                        chooser.getEchConfig().getEchConfigBytes());
        LOGGER.debug("Info: " + ArrayConverter.bytesToHexString(info));
        try {
            this.hpkeSenderContext =
                    hpkeUtil.setupBaseSender(
                            chooser.getEchConfig().getHpkePublicKey(),
                            info,
                            chooser.getEchClientKeyShareEntry());
        } catch (CryptoException e) {
            LOGGER.error("Could not create Hpke Context in EncryptedClientHello");
        }
        LOGGER.debug("Enc: " + ArrayConverter.bytesToHexString(hpkeUtil.getPublicKeySender()));
    }

    private void prepareClientHelloOuterAAD() {
        LOGGER.debug("Preparing ClientHelloOuterAAD");

        // determine encrypted innerclienthelloLength
        int clientHelloInnerLength = this.clientHelloInnerValue.length;
        clientHelloInnerLength += msg.getEncodedClientHelloInnerPadding().getValue().length;
        // payloadLength is this + tag length
        int payloadLength = clientHelloInnerLength + echConfig.getHpkeAeadFunction().getTagLength();
        EncryptedClientHelloExtensionMessage encryptedClientHelloExtensionMessage =
                msg.getEncryptedClientHelloExtensionMessage();
        // set payload to zero values
        encryptedClientHelloExtensionMessage.setPayload(new byte[payloadLength]);
        encryptedClientHelloExtensionMessage.setPayloadLength(payloadLength);

        // set self as the outer clienthello
        super.prepareHandshakeMessageContents();

        // copy session id from inner clienthello
        msg.setSessionId(sessionId);

        // overwrite the SNI extension with GREASE/dummy values
        ServerNameIndicationExtensionMessage serverNameIndicationExtensionMessage =
                msg.getExtension(ServerNameIndicationExtensionMessage.class);
        if (serverNameIndicationExtensionMessage != null) {
            byte[] serverName = chooser.getEchConfig().getPublicDomainName();
            ServerNamePair pair =
                    new ServerNamePair(chooser.getConfig().getSniType().getValue(), serverName);
            serverNameIndicationExtensionMessage.getServerNameList().clear();
            serverNameIndicationExtensionMessage.getServerNameList().add(pair);
            ServerNameIndicationExtensionSerializer serializer =
                    new ServerNameIndicationExtensionSerializer(
                            serverNameIndicationExtensionMessage);
            ServerNameIndicationExtensionPreparator preparator =
                    new ServerNameIndicationExtensionPreparator(
                            chooser, serverNameIndicationExtensionMessage);
            preparator.prepare();
            serverNameIndicationExtensionMessage.setExtensionBytes(serializer.serialize());
        }
        // overwrite the ALPN extension with GREASE/dummy values
        AlpnExtensionMessage alpnExtensionMessage = msg.getExtension(AlpnExtensionMessage.class);
        if (alpnExtensionMessage != null) {
            List<AlpnEntry> alpnEntryList = new LinkedList<>();
            alpnEntryList.add(new AlpnEntry(chooser.getConfig().getDefaultSelectedAlpnProtocol()));
            alpnExtensionMessage.setAlpnEntryList(alpnEntryList);
        }
        // overwrite PSK with GREASE/dummy values
        PreSharedKeyExtensionMessage preSharedKeyExtensionMessage =
                msg.getExtension(PreSharedKeyExtensionMessage.class);
        if (preSharedKeyExtensionMessage != null) {
            for (PSKIdentity pskIdentity : preSharedKeyExtensionMessage.getIdentities()) {
                // overwrite with random bytes
                byte[] randomIdentity = new byte[pskIdentity.getIdentity().getValue().length];
                chooser.getContext().getTlsContext().getRandom().nextBytes(randomIdentity);
                ModifiableVariableFactory.safelySetValue(pskIdentity.getIdentity(), randomIdentity);
                // also overwrite the obfuscated_ticket_age
                byte[] randomObfuscatedTicketAge = new byte[ExtensionByteLength.TICKET_AGE_LENGTH];
                chooser.getContext()
                        .getTlsContext()
                        .getRandom()
                        .nextBytes(randomObfuscatedTicketAge);
                ModifiableVariableFactory.safelySetValue(
                        pskIdentity.getObfuscatedTicketAge(), randomObfuscatedTicketAge);
            }
            for (PSKBinder pskBinder : preSharedKeyExtensionMessage.getBinders()) {
                // overwrite with random bytes
                byte[] randomBinder = new byte[pskBinder.getBinderEntry().getValue().length];
                chooser.getContext().getTlsContext().getRandom().nextBytes(randomBinder);
                ModifiableVariableFactory.safelySetValue(pskBinder.getBinderEntry(), randomBinder);
            }
        }
        // finally update the extension bytes of msg
        EncryptedClientHelloPreparator preparator =
                new EncryptedClientHelloPreparator(chooser, message);
        preparator.prepareExtensions();
        preparator.prepareExtensionLength();
    }

    private void prepareEncryptClientHelloOuter() {
        byte[] aad =
                msg.getSerializer(chooser.getContext().getTlsContext())
                        .serializeHandshakeMessageContent();
        LOGGER.debug("AAD: " + ArrayConverter.bytesToHexString(aad));

        byte[] plaintext =
                ArrayConverter.concatenate(
                        clientHelloInnerValue, msg.getEncodedClientHelloInnerPadding().getValue());
        LOGGER.debug("plaintext: " + ArrayConverter.bytesToHexString(plaintext));
        try {
            byte[] payload = hpkeSenderContext.seal(aad, plaintext);
            LOGGER.debug("payload: " + ArrayConverter.bytesToHexString(payload));

            EncryptedClientHelloExtensionMessage outerExtensionMessage =
                    msg.getEncryptedClientHelloExtensionMessage();
            outerExtensionMessage.setPayload(payload);
            // also serialize it again
            EncryptedClientHelloExtensionSerializer serializer =
                    new EncryptedClientHelloExtensionSerializer(outerExtensionMessage);
            byte[] newContent = serializer.serialize();
            outerExtensionMessage.setExtensionBytes(newContent);
        } catch (CryptoException e) {
            LOGGER.error("Could not encrypt the inner ClientHello");
        }
    }
}
