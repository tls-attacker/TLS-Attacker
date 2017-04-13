/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.dtls.record;

import de.rub.nds.tlsattacker.dtls.record.HandshakeFragmentHandler;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.BeforeClass;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class HandshakeFragmentHandlerTest {
    //
    // static byte[] serverHelloMessageHeader =
    // ArrayConverter.hexStringToByteArray("030000170000000000000017");
    //
    // static byte[] serverHelloMessage = ArrayConverter
    // .hexStringToByteArray("feff149c5cc753b1e17b2652f33f9fb4f357eeaec8fce5");
    //
    // static byte[] certificateMessageHeader =
    // ArrayConverter.hexStringToByteArray("0b00030e000000000000030e");
    //
    // static byte[] certificateMessage = ArrayConverter
    // .hexStringToByteArray("00030b00030830820304308201ec020900d0f4245a0e4132f5300d06092a"
    // +
    // "864886f70d01010b05003044310b3009060355040613024445310c300a06035504080c036e7277310c300a060355040a0c03626c61310c300a"
    // +
    // "060355040b0c03626c61310b300906035504030c02626c301e170d3135303732323137333434325a170d3235303731393137333434325a3044"
    // +
    // "310b3009060355040613024445310c300a06035504080c036e7277310c300a060355040a0c03626c61310c300a060355040b0c03626c61310b"
    // +
    // "300906035504030c02626c30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5b35dcf8034fd6f0d2220de29"
    // +
    // "7a1c7b9de644d37d0e536fece3fc741bd181e0f7ccd3d224fbb813ed941e52bd943060fc4c51174bf50eef96b71c453d275072ad45ddba68c9"
    // +
    // "909dd2692673048f9eeb1485ea9d3ecd33f7d1e91cf2e7ff3e50e62c4543ee5bbbdb9f3ec5763bb5a2ff2a45ccee9828f708cc17db60abba9d"
    // +
    // "f571afe62f5064ecd96470514ed2ac214cebfe624893ff5f62fdecd5969b8915eb0fba8fe5d2355833f1000dfcbafc0842b71943636c127a94"
    // +
    // "88f7056da18213889f91d63c7baaddc9c032581bcd4b37f58f93b550b0ccbc2026460a12af537dc812e84bf89d362ff737046ed6c5b0507efd"
    // +
    // "d751cbb7c03211e287da9f7ea5aa730203010001300d06092a864886f70d01010b0500038201010065728672ed0f02abaf84945ea13aa66c5b"
    // +
    // "90b8bb8d9cfeda47dffc80b8125f5fd76867920dfd7138679f03bf801d0640e473618a6ecb6a16bbf2fac13d8a621a09ed4e823658777d6c4f"
    // +
    // "68ddbb549acb67ed547aac153c85a707da0eeae53210196bbdcb2463f6ded663345d7e0fb780f29e03301100e6028ad520feebedab74aa8dd6"
    // +
    // "26c3d5b4412c07e844618e6f7ccd731303277e028a24543da4a226c3d128162e7edfcfb1d45daff0e73fd3ba984836f68b746b18403afcd06a"
    // +
    // "bd99c967a684de7df75abf8783ba5148d02aa156a334f8bec4f37debedf9ee16c9222a15f66fee055baaf40cbfed9f95f2e00019eeb67d72d9"
    // + "0afed2d8f3abafdff409b8");
    //
    // static byte[] serverDoneMessageHeader =
    // ArrayConverter.hexStringToByteArray("0e00000004FF000000000000");
    //
    // static Record message1Record, message2Variant1Record,
    // message2Variant2Record1, message2Variant2Record2,
    // message2Variant2Record3, message2Variant3Record1,
    // message2Variant3Record2, message2Variant3Record3,
    // message2Variant3Record4, message2Variant3Record5,
    // message2Variant3Record6, message2Variant3Record7,
    // message3Record;
    //
    // @BeforeClass
    // public static void prepareRecords() {
    // message1Record = new Record();
    // message1Record.setContentType((byte) 22);
    // message2Variant1Record = new Record();
    // message2Variant1Record.setContentType((byte) 22);
    // message2Variant2Record1 = new Record();
    // message2Variant2Record1.setContentType((byte) 22);
    // message2Variant2Record2 = new Record();
    // message2Variant2Record2.setContentType((byte) 22);
    // message2Variant2Record3 = new Record();
    // message2Variant2Record3.setContentType((byte) 22);
    // message2Variant3Record1 = new Record();
    // message2Variant3Record1.setContentType((byte) 22);
    // message2Variant3Record2 = new Record();
    // message2Variant3Record2.setContentType((byte) 22);
    // message2Variant3Record3 = new Record();
    // message2Variant3Record3.setContentType((byte) 22);
    // message2Variant3Record4 = new Record();
    // message2Variant3Record4.setContentType((byte) 22);
    // message2Variant3Record5 = new Record();
    // message2Variant3Record5.setContentType((byte) 22);
    // message2Variant3Record6 = new Record();
    // message2Variant3Record6.setContentType((byte) 22);
    // message2Variant3Record7 = new Record();
    // message2Variant3Record7.setContentType((byte) 22);
    // message3Record = new Record();
    // message3Record.setContentType((byte) 22);
    //
    // message1Record
    // .setProtocolMessageBytes(ArrayConverter.concatenate(serverHelloMessageHeader,
    // serverHelloMessage));
    //
    // message2Variant1Record.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000000000012C"),
    // Arrays.copyOfRange(certificateMessage, 0, 300),
    // ArrayConverter.hexStringToByteArray("0b00030e000000012C00012C"),
    // Arrays.copyOfRange(certificateMessage, 300, 600),
    // ArrayConverter.hexStringToByteArray("0b00030e00000002580000B6"),
    // Arrays.copyOfRange(certificateMessage, 600, 782)));
    //
    // message2Variant2Record1.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000000000012C"),
    // Arrays.copyOfRange(certificateMessage, 0, 300)));
    //
    // message2Variant2Record2.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000012C00012C"),
    // Arrays.copyOfRange(certificateMessage, 300, 600)));
    //
    // message2Variant2Record3.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e00000002580000B6"),
    // Arrays.copyOfRange(certificateMessage, 600, 782)));
    //
    // message2Variant3Record1.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e0000000000000080"),
    // Arrays.copyOfRange(certificateMessage, 0, 128)));
    // message2Variant3Record2.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000006400009C"),
    // Arrays.copyOfRange(certificateMessage, 100, 256)));
    // message2Variant3Record3.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e0000000100000080"),
    // Arrays.copyOfRange(certificateMessage, 256, 384)));
    // message2Variant3Record4.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000012C0000D4"),
    // Arrays.copyOfRange(certificateMessage, 300, 512)));
    // message2Variant3Record5.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e0000000200000080"),
    // Arrays.copyOfRange(certificateMessage, 512, 640)));
    // message2Variant3Record6.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e0000000280000080"),
    // Arrays.copyOfRange(certificateMessage, 640, 768)));
    // message2Variant3Record7.setProtocolMessageBytes(ArrayConverter.concatenate(
    // ArrayConverter.hexStringToByteArray("0b00030e000000030000000E"),
    // Arrays.copyOfRange(certificateMessage, 768, 782)));
    //
    // message3Record.setProtocolMessageBytes(serverDoneMessageHeader);
    // }
    //
    // HandshakeFragmentHandler hfh = new HandshakeFragmentHandler();
    //
    // @Test
    // public void testProcessHandshakeRecord() {
    // byte[] result;
    // byte[] expectedResult;
    //
    // hfh.processHandshakeRecord(message1Record);
    // result = hfh.getHandshakeMessage();
    // expectedResult = ArrayConverter.concatenate(serverHelloMessageHeader,
    // serverHelloMessage);
    //
    // assertArrayEquals("Check unfragmentened message", expectedResult,
    // result);
    //
    // hfh.flush();
    // hfh.processHandshakeRecord(message2Variant1Record);
    // result = hfh.getHandshakeMessage();
    // expectedResult = ArrayConverter.concatenate(certificateMessageHeader,
    // certificateMessage);
    //
    // assertArrayEquals("Check fragmented message in single record",
    // expectedResult, result);
    //
    // hfh.flush();
    // hfh.processHandshakeRecord(message2Variant2Record1);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("One of three fragment parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant2Record3);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Two of three fragment parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant2Record2);
    // result = hfh.getHandshakeMessage();
    // expectedResult = ArrayConverter.concatenate(certificateMessageHeader,
    // certificateMessage);
    //
    // assertArrayEquals("Check fragmented message (3 fragments)",
    // expectedResult, result);
    //
    // hfh.flush();
    //
    // hfh.processHandshakeRecord(message2Variant3Record6);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("One of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record5);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Two of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record3);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Three of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record2);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Four of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record2);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Duplicate fragment, no new information, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record7);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Five of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record1);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Six of seven fragments parsed, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record2);
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Duplicate fragment, no new information, no bytes should be returned",
    // result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record4);
    // result = hfh.getHandshakeMessage();
    //
    // assertArrayEquals("Check fragmented message (7 fragments, partly overlapping, differen fragment sizes)",
    // expectedResult, result);
    //
    // hfh.processHandshakeRecord(message2Variant3Record6);
    // result = hfh.getHandshakeMessage();
    //
    // assertArrayEquals("Duplicate fragment, but message already complete, check correct message return",
    // expectedResult, result);
    //
    // hfh.flush();
    // hfh.processHandshakeRecord(message3Record);
    // hfh.setExpectedHandshakeMessageSeq(1279);
    // result = hfh.getHandshakeMessage();
    // expectedResult = serverDoneMessageHeader;
    //
    // assertArrayEquals(
    // "Check message consisting just of handshake message header, no content and check message with sequence "
    // + "number different from zero.", expectedResult, result);
    // }
    //
    // @Test
    // public void testCreateCompleteHandshakeMessageHeader() {
    // byte[] result = hfh.createCompleteHandshakeMessageHeader((byte) 0x00, 0,
    // 0);
    // byte[] expectedResult =
    // ArrayConverter.hexStringToByteArray("000000000000000000000000");
    //
    // assertArrayEquals("Check 'all zero' input", expectedResult, result);
    //
    // result = hfh.createCompleteHandshakeMessageHeader((byte) 0x9B, 5316,
    // 897461);
    // expectedResult =
    // ArrayConverter.hexStringToByteArray("9B0DB1B514C40000000DB1B5");
    //
    // assertArrayEquals("Check some input", expectedResult, result);
    //
    // result = hfh.createCompleteHandshakeMessageHeader((byte) 0xFF, 65535,
    // 16777215);
    // expectedResult =
    // ArrayConverter.hexStringToByteArray("FFFFFFFFFFFF000000FFFFFF");
    //
    // assertArrayEquals("Check max input", expectedResult, result);
    // }
    //
    // @Test
    // public void testGetHandshakeMessage() {
    // loadServerHelloMessasge();
    // byte[] result = hfh.getHandshakeMessage();
    // byte[] expectedResult =
    // ArrayConverter.concatenate(serverHelloMessageHeader, serverHelloMessage);
    //
    // assertArrayEquals("Check correct return of loaded message",
    // expectedResult, result);
    //
    // hfh.flush();
    // loadServerHelloMessageIncomplete();
    // result = hfh.getHandshakeMessage();
    //
    // assertNull("Check null return when message incomplete", result);
    // }
    //
    // @Test
    // public void testCheckHandshakeMessageAvailable() {
    // loadServerHelloMessasge();
    // boolean result = hfh.checkHandshakeMessageAvailable(0);
    //
    // assertTrue("Check availability of loaded message", result);
    //
    // hfh.flush();
    // loadServerHelloMessageIncomplete();
    // result = hfh.checkHandshakeMessageAvailable(0);
    //
    // assertFalse("Check if uncompletely loaded message is not available",
    // result);
    // }
    //
    // @Test
    // public void testFragmentHandshakeMessage() {
    // byte[] result = hfh.fragmentHandshakeMessage(
    // ArrayConverter.concatenate(certificateMessageHeader, certificateMessage),
    // 10000);
    // byte[] expectedResult =
    // ArrayConverter.concatenate(certificateMessageHeader, certificateMessage);
    //
    // assertArrayEquals("Check unfragmented message:", expectedResult, result);
    //
    // result =
    // hfh.fragmentHandshakeMessage(ArrayConverter.concatenate(certificateMessageHeader,
    // certificateMessage),
    // 403);
    // expectedResult =
    // ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("0b00030e0000000000000187"),
    // Arrays.copyOf(certificateMessage, 391),
    // ArrayConverter.hexStringToByteArray("0b00030e0000000187000187"),
    // Arrays.copyOfRange(certificateMessage, 391, 782));
    //
    // assertArrayEquals("Check fragmented message (two fragments):",
    // expectedResult, result);
    //
    // result =
    // hfh.fragmentHandshakeMessage(ArrayConverter.concatenate(certificateMessageHeader,
    // certificateMessage),
    // 362);
    // expectedResult =
    // ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("0b00030e000000000000015E"),
    // Arrays.copyOf(certificateMessage, 350),
    // ArrayConverter.hexStringToByteArray("0b00030e000000015E00015E"),
    // Arrays.copyOfRange(certificateMessage, 350, 700),
    // ArrayConverter.hexStringToByteArray("0b00030e00000002BC000052"),
    // Arrays.copyOfRange(certificateMessage, 700, 782));
    //
    // assertArrayEquals("Check fragmented message (three fragments):",
    // expectedResult, result);
    //
    // result =
    // hfh.fragmentHandshakeMessage(ArrayConverter.concatenate(certificateMessageHeader,
    // certificateMessage),
    // 112);
    // expectedResult =
    // ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("0b00030e0000000000000064"),
    // Arrays.copyOf(certificateMessage, 100),
    // ArrayConverter.hexStringToByteArray("0b00030e0000000064000064"),
    // Arrays.copyOfRange(certificateMessage, 100, 200),
    // ArrayConverter.hexStringToByteArray("0b00030e00000000C8000064"),
    // Arrays.copyOfRange(certificateMessage, 200, 300),
    // ArrayConverter.hexStringToByteArray("0b00030e000000012c000064"),
    // Arrays.copyOfRange(certificateMessage, 300, 400),
    // ArrayConverter.hexStringToByteArray("0b00030e0000000190000064"),
    // Arrays.copyOfRange(certificateMessage, 400, 500),
    // ArrayConverter.hexStringToByteArray("0b00030e00000001F4000064"),
    // Arrays.copyOfRange(certificateMessage, 500, 600),
    // ArrayConverter.hexStringToByteArray("0b00030e0000000258000064"),
    // Arrays.copyOfRange(certificateMessage, 600, 700),
    // ArrayConverter.hexStringToByteArray("0b00030e00000002BC000052"),
    // Arrays.copyOfRange(certificateMessage, 700, 782));
    //
    // assertArrayEquals("Check fragmented message (eight fragments):",
    // expectedResult, result);
    // }
    //
    // private void loadServerHelloMessasge() {
    // List<Record> recordList = new ArrayList<>();
    // BitSet messageBitmask = new BitSet();
    // messageBitmask.set(0,
    // message1Record.getProtocolMessageBytes().getValue().length, true);
    // recordList.add(message1Record);
    // hfh.handshakeMessageRecordMap.put(0, recordList);
    // hfh.handshakeMessageReassembleBitmaskMap.put(0, messageBitmask);
    // hfh.reassembledHandshakeMessageMap.put(0,
    // message1Record.getProtocolMessageBytes().getValue());
    // }
    //
    // private void loadServerHelloMessageIncomplete() {
    // List<Record> recordList = new ArrayList<>();
    // BitSet messageBitmask = new BitSet(12);
    // hfh.handshakeMessageRecordMap.put(0, recordList);
    // hfh.handshakeMessageReassembleBitmaskMap.put(0, messageBitmask);
    // hfh.reassembledHandshakeMessageMap.put(0, new byte[] { 0, 0, 0, 0, 0, 0,
    // 0, 0, 0, 0, 0, 0 });
    // }

}
