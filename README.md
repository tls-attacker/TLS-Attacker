# TLS-Attacker

![GitHub release (latest by date)](https://img.shields.io/github/v/release/tls-attacker/TLS-Attacker)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](https://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=TLS-Attacker)](https://hydrogen.cloud.nds.rub.de/job/TLS-Attacker/)

TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom TLS protocol flow and test it against his TLS library.

**Please note:**  *TLS-Attacker is a research tool intended for TLS developers and pentesters. There is no GUI and no green/red lights.*

## Compiling and Running

In order to compile and use TLS-Attacker, you need to have Java and Maven installed. On Ubuntu you can install Maven by running:

```bash
$ sudo apt-get install maven
```

TLS-Attacker currently needs Java JDK 11 to run.

If you have the correct Java version you can run the maven command from the TLS-Attacker directory:

```bash
$ git clone https://github.com/tls-attacker/TLS-Attacker.git
$ cd TLS-Attacker
$ mvn clean install
```

Alternatively, if you are in a hurry, you can skip the tests by using:

```bash
$ mvn clean install -DskipTests=true
```

The resulting jar files are placed in the "apps" folder.

If you want to use this project as a dependency, you do not have to compile it yourself and can include it in your pom
.xml as follows.

```xml
<dependency>
    <groupId>de.rub.nds.tls.attacker</groupId>
    <artifactId>tls-attacker</artifactId>
    <version>5.2.1</version>
    <type>pom</type>
</dependency>
```

TLS-Attacker ships with demo applications which provide you easy access to TLS-Attacker functionality.

You can run TLS-Attacker as a client with the following command:

```bash
$ cd apps
$ java -jar TLS-Client.jar -connect [host:port]
```

or as a server with:

```bash
$ java -jar TLS-Server.jar -port [port]
```

TLS-Attacker also ships with some example attacks on TLS to show you how easy it is to implement an attack with TLS-Attacker.
You can run those examples with the following command:

```bash
$ java -jar Attacks.jar [Attack] -connect [host:port]
```

Although these example applications are very powerful in itself, TLS-Attacker unleashes its full potential when used as a programming library.

## Code Structure

TLS-Attacker consists of several (maven) projects:
- TLS-Client: The client example application
- TLS-Core: The protocol stack and heart of TLS-Attacker
- TLS-Mitm: A prototype for MitM workflows
- TLS-Server: The server example application
- TLS-Proxy: Use TLS-Attacker for SSLSockets
- TraceTool: Inspection and modification of TLS-Attacker workflow traces
- Transport: Transport utilities for lower layers
- Utils: A collection of utility classes

![TLS-Attacker design](https://github.com/tls-attacker/TLS-Attacker/blob/master/resources/figures/design.png)

You can find more information about these modules in the Wiki.

## Features

Currently, the following features are supported:
- SSL 3, TLS versions 1.0 (RFC-2246), 1.1 (RFC-4346), 1.2 (RFC-5246), and 1.3 (RFC-8446)
- SSL 2 (Partially supported)
- (EC)DH(E), RSA, PSK, SRP, GOST and ANON key exchange algorithms
- CBC, AEAD and Streamciphers (AES, CAMELLIA, DES, 3DES, IDEA, RC2, ARIA, GOST_28147_CNT_IMIT, RC4, SEED, NULL)
- ~300 Cipher suites, ~30 Extensions
- Client and Server
- HTTPS
- Workflows with more than two parties
- Lots of extensions
- Tokenbinding (EC) and Tokenbinding over HTTP
- Sockets
- TLS 1.3 0-RTT
- STARTTLS
- ...

## Usage

Here we present some very simple examples on using TLS-Attacker.

First, you need to start a TLS server (*please do not use public servers*). Please run the keygen.sh script if not done before. For example, you can use an OpenSSL test server:

```
$ cd TLS-Attacker/resources
$ openssl s_server -key rsa1024key.pem -cert rsa1024cert.pem
```

This command starts a TLS server on a port 4433.

If you want to connect to a server, you can use this command:

```bash
$ cd TLS-Attacker/apps
$ java -jar TLS-Client.jar -connect localhost:4433
```

*Note: If this Handshake fails, it is probably because you did not specify a concrete cipher suite. TLS-Attacker will not completely respect server selected cipher suites.*

You can use a different cipher suite, TLS version, or connect to a different port with the following parameters:

```bash
$ java -jar TLS-Client.jar -connect localhost:4433 -cipher TLS_RSA_WITH_AES_256_CBC_SHA -version TLS11
```

In case you are a more experienced developer, you can create your own TLS message flow by writing Java code. For example:

```java
Config config = Config.createConfig();
WorkflowTrace trace = new WorkflowTrace();
trace.addTlsAction(new SendAction(new ClientHelloMessage()));
trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
State state = new State(config, trace);
DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
executor.executeWorkflow();
```

TLS-Attacker uses the concept of WorkflowTraces to define a "TLS message flow". A WorkflowTrace consists of a list of actions which are then executed one after the other. Although for a typical "TLS message flow" only SendAction's and ReceiveAction's are needed, the framework does not stop here and implements a lot of different other actions which can be used to execute even more arbitrary message flows. A list of currently implemented actions with explanations can be found in the Wiki.

We know many of you hate Java. Therefore, you can also use an XML structure and run your customized TLS protocol from XML:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <Send>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </Receive>
</workflowTrace>
```

Given this XML structure is located in TLS-Attacker/apps/workflow.xml, you would just need to execute:

```bash
$ java -jar TLS-Client.jar -connect [host]:[port] -workflow_input workflow.xml
```

## Protocol-Attacker/Layer System

Originally designed to attack the TLS protocol, TLS-Attacker is capable of supporting arbitrary protocols. To this end, TLS-Attacker assigns a layer stack to each connection. This layer stack consists of the different protocol layers the user wants to utilize. With the layer stack, the user can add layers like DTLS, or HTTP (more are WIP) in an arbitrary order.

To send and receive arbitrary messages using a layer stack, the user can define configurations for each layer. These configurations specifiy which messages to send or receive. This also allows the user to specify the layer specific messages/data containers for each layer. For example, one could specify the TLS messages and records TLS-Attacker should send. TLS-Attacker would encapsulate the given TLS messages into the records automatically.

## Modifiable Variables

TLS-Attacker uses the concept of Modifiable Variables to allow runtime modifications to predefined Workflows. Modifiable variables allow one to set modifications to basic types after or before their values are actually set. When their actual values are determined and one tries to access the value via getters the original value will be returned in a modified form accordingly. More details on this concept can be found at https://github.com/tls-attacker/ModifiableVariable.

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
    <Send>
        <messages>
            <ClientHello>
                <extensions>
                    <ECPointFormat/>
                    <HeartbeatExtension/>
                    <EllipticCurves/>
                </extensions>
            </ClientHello>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ServerHello>
                <extensions>
                    <ECPointFormat/>
                </extensions>
            </ServerHello>
            <Certificate/>
            <ServerHelloDone/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <RSAClientKeyExchange>
                <computations/>
            </RSAClientKeyExchange>
            <ChangeCipherSpec/>
            <Finished/>
        </messages>
    </Send>
    <Receive>
        <expectedMessages>
            <ChangeCipherSpec/>
            <Finished/>
        </expectedMessages>
    </Receive>
    <Send>
        <messages>
            <Heartbeat>
                <payloadLength>
                    <IntegerExplicitValueModification>
                        <explicitValue>20000</explicitValue>
                    </IntegerExplicitValueModification>
                </payloadLength>
            </Heartbeat>
        </messages>
    </Send>
    <Receive>
        <messages>
            <Heartbeat/>
        </messages>
    </Receive>
</workflowTrace>
```

As you can see, we explicitly increased the payload length of the heartbeat message by 20000.
If you run the attack against the vulnerable server (e.g., OpenSSL 1.0.1f), you should see a valid heartbeat response.

Further examples on attacks and further explanations on TLS-Attacker can be found in the wiki.

## Advanced Features

Some actions require context, or configuration to be executed correctly. For example, if TLS-Attacker tries to send a ClientHello message, it needs to know which values to
put into the message, e.g., which Cipher suites or which protocol version to use. TLS-Attacker draws this information
from a configuration file (default located in TLS-Core/src/main/resources/default_config.xml).
Values which are determined at runtime are stored in the TlsContext. When a value which is normally selected from the context is missing (because a message was not yet received), the default value from the Config is selected. You can specify your own configuration file from command line with the "-config" parameter. Note that if you do not explicitly define a default value in the config file, TLS-Attacker fills
this gap with hardcoded values (which are equal to the provided default config). More details on how to customize TLS-Attacker can be found in the wiki.

## Acknowledgements

We would like to thank everyone who has contributed to the TLS-Attacker project.

A special thanks goes to the following peoples for their notable contributions:

Muhammad Abubakar, Fabian Albert, Panneer Selvam Annadurai, Nimrod Aviram, Philipp Brinkmann, Till Budde, Florian Bürger, Christoph Buttler, Jens Carl, Raphael Dietrich, Felix Dreissig, Bastian Ebach, Malena Ebert, Robert Engel, Nils Engelbertz, Paul Fiterau Brostean, Janis Fliegenschmidt, Alexander Freiherr von Buddenbrock, Matthias Manfred Geuchen, Alexander Glasfort, Nils Hanke, Lucas Hartmann, Bastian Haverkamp, Nico Heitmann, Jannik Hölling, Selami Hoxha, Kevin Jagla, Nils Kafka, Jan Kaiser, Anton Khristoforov, Felix Kleine-Wilde, Mario Korth, Sebastian Krois, Christian Krug, Felix Lange, Florian Linsner, Christian Mainka, Jonas Moos, Simon Nachtigall, Simon Nattefort, Philipp Nieting, Niels Pahl, Christoph Penkert, Florian Pfützenreuter, Adrian Pinner, Malte Poll, Christian Pressler, Tim Reisach, Philip Riese, Nils Luca Rudminat, Henrik Schaefer, Marten Schmidt, Conrad Schmidt, Daniel Siegert, Tim Storm, Rigers Sulku, Bjarne Tempel, Matthias Terlinde, Jonas Thiele, Pierre Tilhaus, Joshua Waldner, Patrick Weixler, Philipp Wirth, Asli Yardim, Dennis Ziebart, David Ziemann, Philipp Ziemke

Further contributions and pull requests are welcome.

## Scientific Papers

The basic concepts behind TLS-Attacker and several attacks are described in the following paper:
- Juraj Somorovsky. Systematic Fuzzing and Testing of TLS Libraries. ACM CCS'16. https://www.nds.rub.de/research/publications/systematic-fuzzing-and-testing-tls-libraries

Below, we list recent scientific studies that utilized TLS-Attacker. You can find the full list in the [Wiki](https://github.com/tls-attacker/TLS-Attacker-Development/wiki/Scientific-Papers-and-Projects)
- Michael Scott. 2023. On TLS for the Internet of Things, in a Post Quantum world.
https://eprint.iacr.org/2023/095
- Yong Wang, Rui Wang, Xin Liu, Donglan Liu, Hao Zhang, Lei Ma, Fangzhe Zhang,
Lili Sun, and Zhenghao Li. 2023. A Framework for TLS Implementation Vulnerability Testing in 5G. In Applied Cryptography and Network Security Workshops, ACNS 2023 Satellite Workshop https://link.springer.com/chapter/10.1007/978-3-031-41181-6_16
- Diana Gratiela Berbecaru and Giuseppe Petraglia. 2023. TLS-Monitor: A Monitor
for TLS Attacks. In 2023 IEEE 20th Consumer Communications & Networking
Conference (CCNC). https://ieeexplore.ieee.org/document/10059989
- Paul Fiterau-Brostean, Bengt Jonsson, Konstantinos Sagonas, and Fredrik Tåquist. 2023. Automata-Based Automated Detection of State Machine Bugs in Protocol
Implementations. In 30th Annual Network and Distributed System Security Symposium, NDSS 2023 https://www.ndss-symposium.org/ndss-paper/automata-based-automated-detection-of-state-machine-bugs-in-protocol-implementations/
- Sven Hebrok, Simon Nachtigall, Marcel Maehren, Nurullah Erinola, Robert Merget, Juraj Somorovsky, and Jörg Schwenk. 2023. We Really Need to Talk About
Session Tickets: A Large-Scale Analysis of Cryptographic Dangers with TLS
Session Tickets. In 32nd USENIX Security Symposium, USENIX Security 2023 https://www.usenix.org/conference/usenixsecurity23/presentation/hebrok
- Nurullah Erinola, Marcel Maehren, Robert Merget, Juraj Somorovsky, and Jörg
Schwenk. 2023. Exploring the Unknown DTLS Universe: Analysis of the DTLS
Server Ecosystem on the Internet. In 32nd USENIX Security Symposium, USENIX
Security 2023 https://www.usenix.org/conference/usenixsecurity23/presentation/erinola
- Ka Lok Wu, Man Hong Hue, Ngai Man Poon, Kin Man Leung, Wai Yin Po,
Kin Ting Wong, Sze Ho Hui, and Sze Yiu Chau. 2023. Back to School: On the
(In)Security of Academic VPNs. In 32nd USENIX Security Symposium, USENIX
Security 2023 https://www.usenix.org/conference/usenixsecurity23/presentation/wu-ka-lok
- Diana Gratiela Berbecaru and Antonio Lioy. 2024. Threat-TLS: A Tool for Threat
Identification in Weak, Malicious, or Suspicious TLS Connections. In Proceedings
of the 19th International Conference on Availability, Reliability and Security (Vienna,
Austria) (ARES ’24) https://dl.acm.org/doi/10.1145/3664476.3670945
- Maximilian Radoy, Sven Hebrok, and Juraj Somorovsky. 2024. In Search of Partitioning Oracle Attacks Against TLS Session Tickets. In 29th European Symposium
on Research in Computer Security (ESORICS) https://link.springer.com/chapter/10.1007/978-3-031-70896-1_16
- Martin Dunsche, Marcel Maehren, Nurullah Erinola, Robert Merget, Nicolai Bissantz, Juraj Somorovsky, and Jörg Schwenk. 2024. With Great Power Come Great
Side Channels: Statistical Timing Side-Channel Analyses with Bounded Type-1
Errors. In 33rd USENIX Security Symposium, USENIX Security 2024 https://www.usenix.org/conference/usenixsecurity24/presentation/dunsche

If you have any research ideas or need support feel free to contact us on Twitter (@ic0nz1 , @jurajsomorovsky , @marcelmaehren , @nerinola1 ) or at https://www.hackmanit.de/.

If TLS-Attacker helps you to find a bug in a TLS implementation, please acknowledge this tool. Thank you!
