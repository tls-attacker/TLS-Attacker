# TLS-Attacker

[![release](https://img.shields.io/badge/Release-v2.0-blue.svg)](https://github.com/RUB-NDS/TLS-Attacker/releases)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![travis](https://travis-ci.org/RUB-NDS/TLS-Attacker.svg?branch=master)](https://travis-ci.org/RUB-NDS/TLS-Attacker)

TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom TLS protocol flow and test it against his TLS library.

**Please note:**  *TLS-Attacker is a research tool intended for TLS developers and pentesters. There is no GUI and no green/red lights. It is the second version and can contain some bugs.*

## Compiling and Running
In order to compile and use TLS-Attacker, you need to have Java installed. Run the maven command from the TLS-Attacker directory:
```bash
$ cd TLS-Attacker
$ ./mvnw clean package
```
Alternatively, if you are in hurry, you can skip the tests by using:
```bash
$ ./mvnw clean package -DskipTests=true
```

TLS-Attacker ships with Demo Applications which allow you easy access to TLS-Attackers functionality.

You can run TLS-Attacker as a client with the following command:
```bash
$ java -jar TLS-Client.jar -connect [host:port]
```
or as a server with:

```bash
$ java -jar TLS-Server.jar -port [port]
```

TLS-Attacker also ships with some example Attacks on TLS to show you how easy it is to implement an Attack with TLS-Attacker.
You can run those examples with the following command:
```bash
$ java -jar Attacks [Attack] -connect [host:port]
```
Although these example Applications are very powerful in itself, TLS-Attacker unleashes its full potential when used as a programming library.

## Code Structure
TLS-Attacker consists of several (maven) projects:
- TLS-Core: The protocol stack and heart of TLS-Attacker
- Transport: Transport utilities for lower layers
- Utils: A collection of utility classes
- TLS-Client: The client example Application
- TLS-Server: The server example Application
- Attacks: Implementation of some well-known attacks and vulnerability Tests.
- TLS-Mitm: A prototype MitM Workflows
![TLS-Attacker design](https://github.com/RUB-NDS/TLS-Attacker/blob/master/resources/figures/design.png)

You can find more information about these modules in the Wiki.

## Features
Currently, the following features are supported:
- TLS versions 1.0 (RFC-2246), 1.1 (RFC-4346) 1.2 (RFC-5246) and 1.3 (draft-ietf-tls-tls13-21)
- DTLS 1.2 (RFC-6347)(Currently under Development)
- SSL 2 (Client/Server Hello)
- (EC)DH and RSA key exchange algorithms
- CBC, AEAD and Streamciphers
- TLS client and server
- HTTPS
- MitM (experimental)
- Lots of Extensions
- Tokenbinding (EC) and Tokenbinding over HTTP
- Sockets
- PSK


Full support for the following Extensions: 
- EC Point Formats
- EllipticCurves
- ExtendedMasterSecret
- KeyShare
- MaxFragmentLength
- Padding
- SNI
- Signature and Hash Algorithms
- Supported Versions
- Heartbeat
- Renegotiation
- Tokenbinding

The following Extesions are sendable and receivable but are currently not completely functional:
- ALPN
- Cached Info
- Client Authz
- Client Certificate Type
- Client Certificate Url
- EncryptThenMac
- Server Authz
- Server Certificate Type
- Session Ticket
- Signed Certificate Timestamp
- SRP
- Status Request
- Status Requestv2
- TruncatedHmac
- TrustedCaKeys
- UseSRTP

## Usage
In the following, we present some very simple examples on using TLS-Attacker.

First, you need to start a TLS server (*please do not use public servers*). For example, you can use an OpenSSL test server::
```
$ cd TLS-Attacker/resources
$ openssl s_server -key rsa1024key.pem -cert rsa1024cert.pem
```
This command starts a TLS server on a port 4433.

If you want to connect to a server, you can use this command:
```bash
$ java -jar TLS-Client.jar -connect localhost:4433
```
*Note: If this Handshake fails, it is probably because you did not specify a concrete Ciphersuite. TLS-Attacker will not completely respect Server selected Ciphersuites.*

You can use a different cipher suite, TLS version, or connect to a different port with the following parameters:
```bash
$ java -jar TLS-Client.jar -connect localhost:4433 -cipher TLS_RSA_WITH_AES_256_CBC_SHA -version TLS11
```

The Attacks module contains some attacks, you can for example test for the padding oracle vulnerabilities:
```bash
$ java -jar Attacks.jar padding_oracle -connect localhost:4433 
```

In case you are a more experienced developer, you can create your own TLS message flow. By writing Java code. For example:
```java
Config config = Config.createConfig();
WorkflowTrace trace = new WorkflowTrace();
trace.add(new SendAction(new ClientHelloMessage()));
trace.add(new ReceiveAction(new ServerHelloMessage())));
trace.add(new SendAction(new FinishedMessage()));
State state = new State(config, trace);
DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
executor.execute();

```
TLS-Attacker uses the concept of WorkflowTraces to define a "TLS message flow". A WorkflowTrace consists of a List of Actions which are then executed one after the other.
Although for a typical "TLS message flow" only SendAction's and ReceiveAction's are needed, the Framework does not stop here and implements alot of different other Actions
which can be used to execute even more Arbitrary message flows. A list of currently implemented Actions with explanations can be found in the Wiki.

We know many of you hate Java. Therefore, you can also use an XML structure and run your customized TLS protocol from XML:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <SendAction>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>#
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </SendAction>
    <ReceiveAction>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </ReceiveAction>
    <SendAction>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </SendAction>
    <ReceiveAction>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </ReceiveAction>
</workflowTrace>
```
Given this XML structure is located in workflow.xml, you would just need to execute:
```bash
$ java -jar TLS-Client.jar -connect [host]:[port] -workflow_input workflow.xml
```
## Modifiable Variables
TLS-Attacker uses the concept of Modifiable variables to allow runtime Modifications to predefined Workflows. Modifiable variables allow one to set modifications to basic types after or before their values are actually set. When their actual values are determined and one tries to access the value via getters the original value will be returned in a modified form accordingly. More details on this concept can be found at https://github.com/RUB-NDS/ModifiableVariable. 

```java
ModifiableInteger i = new ModifiableInteger();
i.setOriginalValue(30);
i.setModification(new AddModification(20));
System.out.println(i.getValue());  // 50
```
In this example, we defined a new ModifiableInteger and set its value to 30. Next, we defined a new modification AddModification which simply returns a sum of two integers. We set its value to 20. If we execute the above program, the result 50 is printed. 

We can of course use this concept by constructing our TLS workflows. Imagine you want to test a server for a heartbleed vulnerability. For this purpose, you need to increase the payload length in the heartbeat request. With TLS-Attacker, you can do this as follows:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <SendAction>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>#
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </SendAction>
    <ReceiveAction>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </ReceiveAction>
    <SendAction>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </SendAction>
    <ReceiveAction>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </ReceiveAction>
    <SendAction>
		<messages>
			<Heartbeat>
				<payloadLength>
					<integerExplicitValueModification>
						<explicitValue>20000</explicitValue>
					</integerExplicitValueModification>
				</payloadLength>
			</Heartbeat>
        </messages
    </SendAction>
    <ReceiveAction>
		<Heartbeat/>
    </ReceiveAction>
</workflowTrace>
```
As you can see, we explicitly increased the payload length of the Heartbeat message by 20000.
If you run the attack against the vulnerable server (e.g., OpenSSL 1.0.1f), you should see a valid Heartbeat response.

Further examples on attacks and further explanations on TLS-Attacker can be found in the Wiki.

## Advanced Features
Some Actions require context, or configuration to be executed correctly. For exmaple, if TLS-Attacker tries to send a ClientHello message, it needs to know which values to
put into the message, eg. which Ciphersuites or which protocol version to use. TLS-Attacker draws this information from a configuration file (default located in TLS-Core/src/main/resources/default_config.xml).
Values which are determined at runtime are stored in the TlsContext. When a value which is normally selected from the context is missing (because a message was not yet received), the default value from the Config is selected. You can specify your own configuration file from command line with the "-config" parameter. Note that if you do not explicitly define a default value in the config file, TLS-Attacker fills
this gap with hardcoded values (which are equal to the provided default config). More details on how to customize TLS-Attacker can be found in the wiki.

## Acknowledgements
The following people have contributed code to the TLS-Attacker Project:
- Florian Pfützenreuter: DTLS 1.2
- Felix Lange: EAP-TLS
- Philip Riese: Server implementation, TLS Man-in-the-Middle Prototype
- Christian Mainka: Design support and many implementation suggestions.
- Matthias Terlinde: More TLS-Extensions
- Nurullah Erinola: TLS 1.3 Support
- Lucas Hartmann: TLS-MitM Workflows
- Florian Linsner: PSK
- Pierre Tilhaus: Code quality improvements

Additionally we would like to thank all the other people who have contributed code to the project.

Further contributions and pull requests are welcome.

## TLS-Attacker Projects
The basic concepts behind TLS-Attacker and several attacks are described in the following paper:
- Juraj Somorovsky. Systematic Fuzzing and Testing of TLS Libraries. ACM CCS'16. https://www.nds.rub.de/research/publications/systematic-fuzzing-and-testing-tls-libraries

TLS-Attacker was furthermore used in the following scientific papers and projects:
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. On the Security of TLS 1.3 and QUIC Against Weaknesses in PKCS#1 v1.5 Encryption. ACM CCS'15. https://www.nds.rub.de/research/publications/ccs15/
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. Practical Invalid Curve Attacks on TLS-ECDH. ESORICS'15. https://www.nds.rub.de/research/publications/ESORICS15/
- Quellcode-basierte Untersuchung von kryptographisch relevanten Aspekten der OpenSSL-Bibliothek. https://www.bsi.bund.de/DE/Publikationen/Studien/OpenSSL-Bibliothek/opensslbibliothek.html

If you have any research ideas or need support by using TLS-Attacker (e.g. you want to include it in your test suite), feel free to contact http://www.hackmanit.de/.

If TLS-Attacker helps you to find a bug in a TLS implementation, please acknowledge this tool. Thank you!
