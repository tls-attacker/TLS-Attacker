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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PskSet;
import de.rub.nds.tlsattacker.core.protocol.parser.NewSessionTicketMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewSessionTicketMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketHandler extends HandshakeMessageHandler<NewSessionTicketMessage> {

    public NewSessionTicketHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new NewSessionTicketMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public NewSessionTicketMessagePreparator getPreparator(NewSessionTicketMessage message) {
        return new NewSessionTicketMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public NewSessionTicketMessageSerializer getSerializer(NewSessionTicketMessage message) {
        return new NewSessionTicketMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(NewSessionTicketMessage message) {
        if (tlsContext.getSelectedProtocolVersion().isTLS13()) {
            adjustPskSets(message);
        }
    }

    private void adjustPskSets(NewSessionTicketMessage message) {
        LOGGER.debug("Adjusting PSK-Sets");
        if (tlsContext.getPskSets() == null) {
            tlsContext.setPskSets(new LinkedList<PskSet>());
        }
        PskSet pskSet = new PskSet();
        pskSet.setCipherSuite(tlsContext.getSelectedCipherSuite());
        pskSet.setTicketAgeAdd(message.getTicket().getTicketAgeAdd().getValue());
        pskSet.setPreSharedKeyIdentity(message.getTicket().getIdentity().getValue());
        pskSet.setTicketAge(getTicketAge());
        pskSet.setPreSharedKey(derivePsk(message));
        tlsContext.getPskSets().add(pskSet);

    }

    private String getTicketAge() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        LocalDateTime ticketDate = LocalDateTime.now();

        return ticketDate.format(dateTimeFormatter);
    }

    private byte[] derivePsk(NewSessionTicketMessage message) {
        try {
            LOGGER.debug("Deriving PSK from current session using transscript: "
                    + ArrayConverter.bytesToHexString(tlsContext.getDigest().getRawBytes(), false));
            HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser()
                    .getSelectedCipherSuite());
            DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(tlsContext.getChooser()
                    .getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());
            int macLength = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] resumptionMasterSecret = HKDFunction.deriveSecret(hkdfAlgortihm, digestAlgo.getJavaName(),
                    tlsContext.getMasterSecret(), HKDFunction.RESUMPTION_MASTER_SECRET, tlsContext.getDigest()
                            .getRawBytes());
            LOGGER.debug("Derived ResumptionMasterSecret: " + ArrayConverter.bytesToHexString(resumptionMasterSecret));
            byte[] psk = HKDFunction.expandLabel(hkdfAlgortihm, resumptionMasterSecret, HKDFunction.RESUMPTION, message
                    .getTicket().getTicketNonce().getValue(), macLength);
            LOGGER.debug("Derived PSK: " + ArrayConverter.bytesToHexString(psk));
            return psk;

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(NewSessionTicketHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new byte[0];
    }

}