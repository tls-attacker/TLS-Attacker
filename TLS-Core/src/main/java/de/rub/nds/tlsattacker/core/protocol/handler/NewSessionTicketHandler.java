/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.parser.NewSessionTicketParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewSessionTicketPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewSessionTicketHandler extends HandshakeMessageHandler<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewSessionTicketHandler(TlsContext context) {
        super(context);
    }

    @Override
    public NewSessionTicketParser getParser(byte[] message, int pointer) {
        return new NewSessionTicketParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public NewSessionTicketPreparator getPreparator(NewSessionTicketMessage message) {
        return new NewSessionTicketPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public NewSessionTicketSerializer getSerializer(NewSessionTicketMessage message) {
        return new NewSessionTicketSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(NewSessionTicketMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            if (!tlsContext.isClientFinishedSent()) {
                tlsContext.setCachedNewSessionTicketMessage(message);
                return;
            }
            adjustPskSets(message);
        } else {
            tlsContext.setSessionTicketTLS(message.getTicket().getIdentity().getValue());
            tlsContext.getConfig().setTlsSessionTicket(message.getTicket().getIdentity().getValue());
        }
    }

    private void adjustPskSets(NewSessionTicketMessage message) {
        LOGGER.debug("Adjusting PSK-Sets");
        List<PskSet> pskSets = tlsContext.getPskSets();
        if (pskSets == null) {
            pskSets = new LinkedList<>();
        }
        PskSet pskSet = new PskSet();
        pskSet.setCipherSuite(tlsContext.getChooser().getSelectedCipherSuite());
        if (message.getTicket().getTicketAgeAdd() != null) {
            pskSet.setTicketAgeAdd(message.getTicket().getTicketAgeAdd().getValue());
        } else {
            LOGGER.warn("No TicketAge specified in SessionTicket");
        }
        if (message.getTicket().getIdentity() != null) {
            pskSet.setPreSharedKeyIdentity(message.getTicket().getIdentity().getValue());
        } else {
            LOGGER.warn("No Identity in ticket. Using new byte[] instead");
            pskSet.setPreSharedKeyIdentity(new byte[0]);
        }
        pskSet.setTicketAge(getTicketAge());
        pskSet.setPreSharedKey(derivePsk(message));
        LOGGER.debug("Adding PSK Set");
        pskSets.add(pskSet);
        tlsContext.setPskSets(pskSets);

    }

    private String getTicketAge() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        LocalDateTime ticketDate = LocalDateTime.now();

        return ticketDate.format(dateTimeFormatter);
    }

    private byte[] derivePsk(NewSessionTicketMessage message) {
        try {
            LOGGER.debug("Deriving PSK from current session");
            HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser().getSelectedCipherSuite());
            DigestAlgorithm digestAlgo =
                AlgorithmResolver.getDigestAlgorithm(tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext
                    .getChooser().getSelectedCipherSuite());
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] resumptionMasterSecret =
                HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(), tlsContext.getMasterSecret(),
                    HKDFunction.RESUMPTION_MASTER_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setResumptionMasterSecret(resumptionMasterSecret);
            LOGGER.debug("Derived ResumptionMasterSecret: " + ArrayConverter.bytesToHexString(resumptionMasterSecret));
            LOGGER.debug("Derived Master Secret: " + ArrayConverter.bytesToHexString(tlsContext.getMasterSecret()));
            LOGGER.debug("Raw Bytes: " + ArrayConverter.bytesToHexString(tlsContext.getDigest().getRawBytes()));
            byte[] psk =
                HKDFunction.expandLabel(hkdfAlgorithm, resumptionMasterSecret, HKDFunction.RESUMPTION, message
                    .getTicket().getTicketNonce().getValue(), macLength);
            LOGGER.debug("Derived PSK Neu: " + ArrayConverter.bytesToHexString(psk));
            return psk;

        } catch (NoSuchAlgorithmException | CryptoException ex) {
            LOGGER.error("DigestAlgorithm for psk derivation unknown");
            throw new WorkflowExecutionException(ex.toString());
        }
    }

}
