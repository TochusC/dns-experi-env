# GoDNS

[![madewithlove](https://img.shields.io/badge/made_with-%E2%9D%A4-red?style=for-the-badge&labelColor=orange&style=flat-square)](https://github.com/TochusC/godns)
![Go Version](https://img.shields.io/github/go-mod/go-version/tochusc/godns/master?filename=go.mod&style=flat-square)
![Latest Version](https://img.shields.io/github/v/tag/tochusc/godns?label=latest&style=flat-square)
![License](https://img.shields.io/github/license/tochusc/godns?style=flat-square)
[![GoDoc](https://godoc.org/github.com/tochusc/godns?status.svg)](https://godoc.org/github.com/tochusc/godns)

[简体中文](../../README.md) | [English](README.md)

GoDNS is a fast, flexible **experimental** DNS server designed to help developers and researchers explore and experiment with various features of the DNS protocol.

## Table of Contents

- [GoDNSServer](#godnsserver)
- [Examples](#examples)
- [Constructing and Generating DNS Replies](#constructing-and-generating-dns-replies)
- [dns Package](#dns-package)
- [xlayers Subpackage](#xlayers-subpackage)
- [xperi Subpackage](#xperi-subpackage)

## GoDNSServer

`GoDNSServer` is a top-level wrapper for the DNS server, consisting of three parts:

1. **ServerConfig**: Configuration for the DNS server.
2. **Netter**: Packet handler that receives, parses, and sends packets while maintaining connection state.
3. **Responser**: DNS responder that responds, parses, and constructs DNS replies.

```go
type GoDNSServer struct {
    ServerConfig DNSServerConfig
    Netter       Netter
    Responer     Responser
}

// Start the GoDNS server!
func (s *GoDNSServer) Start()
```

### Netter

*`Netter` Packet Listener: Receives, parses, sends packets, and maintains connection state.*

```go
type Netter struct { // size=16 (0x10)
    Config NetterConfig
}

// Send function is used to send packets
func (n *Netter) Send(connInfo ConnectionInfo, data []byte)

// Sniff function listens on a specified port and returns a channel of connection information
func (n *Netter) Sniff() chan ConnectionInfo

// handleListener function handles TCP connections
func (n *Netter) handleListener(lstr net.Listener, connChan chan ConnectionInfo)

// handlePktConn function handles packet connections
func (n *Netter) handlePktConn(pktConn net.PacketConn, connChan chan ConnectionInfo)

// handleStreamConn function handles stream connections
func (n *Netter) handleStreamConn(conn net.Conn, connChan chan ConnectionInfo)
```

### Responser

*`Responser` DNS Responder: Responds to DNS queries, parses, and constructs DNS replies.*

`Responser` is an interface. The struct implementing this interface will generate DNS reply information based on DNS query information.

```go
type Responser interface { // size=16 (0x10)
    // Response generates DNS reply information based on DNS query data.
    // Its argument is:
    //   - qInfo QueryInfo, DNS query information
    // It returns:
    //   - ResponseInfo, DNS reply information
    //   - error, error information
    Response(ConnectionInfo) (dns.DNSMessage, error)
}
```

## Examples

With just a few lines of code, you can start a basic GoDNS server:

```go
// Create a DNS server
server := godns.GoDNSServer{
    ServerConfig: sConf,
    Netter: godns.Netter{
        Config: godns.NetterConfig{
        Port: sConf.Port,
            MTU:  sConf.MTU,
        },
    },
    Responer: &DullResponser{
        ServerConf: sConf,
    },
}
server.Start()
```

## Constructing and Generating DNS Replies

You can customize how DNS replies are generated by implementing the `Responser` interface.

The `responser.go` file provides several `Responser` implementations and many auxiliary functions for reference.

## dns Package

The `dns` package uses Go's built-in implementation to provide DNS message encoding and decoding capabilities, which can be used for constructing and parsing DNS messages.

`DNSMessage` represents the structure of a DNS protocol message.

```go
type DNSMessage struct {
    // DNS message header
    Header DNSHeader // DNS header
    // Sections of the DNS message
    Question   DNSQuestionSection // Question section
    Answer     DNSResponseSection // Answer section
    Authority  DNSResponseSection // Authority section
    Additional DNSResponseSection // Additional section
}
```

Each structure in the `dns` package generally implements the following methods:

```go
// Decode from buffer
func (s *struct) DecodeFromBuffer(buffer []byte, offset int) (int, error)

// Encode to byte stream
func (s *struct) Encode() []byte

// Encode to buffer
func (s *struct) EncodeToBuffer(buffer []byte) (int, error)

// Get the actual size of the structure
func (s *struct) Size() int

// Get the string representation of the structure
func (s *struct) String() string

// [Partially implemented] Check if two structures are equal
func (s *struct) Equal(other *struct) bool
```

These methods make it easy to encode and decode DNS messages.

The `dns` package has no strict format constraints and supports encoding/decoding of unknown types of resource records, allowing it to construct and parse DNS messages as needed for experimentation.

## xperi Subpackage

The `xperi` package implements some experimental functions, especially those related to DNSSEC, including:

- `ParseKeyBase64`: Parses Base64-encoded DNSKEY into byte format.
- `CalculateKeyTag`: Calculates the Key Tag of a DNSKEY.
- `GenerateRDATADNSKEY`: Generates DNSKEY RDATA based on parameters.
- `GenerateRDATARRSIG`: Signs an RRSET and generates RRSIG RDATA.
- `GenerateRDATADS`: Generates DS RDATA for a DNSKEY.
- `GenerateRRDNSKEY`: Generates a DNSKEY RR.
- `GenerateRRRRSIG`: Signs an RRSET and generates RRSIG RR.
- `GenerateRRDS`: Generates DS RR for a DNSKEY.
- `GenRandomRRSIG`: Generates a random RRSIG RDATA.
- `GenWrongKeyWithTag`: Generates a DNSKEY RDATA with a specified incorrect KeyTag.
- `GenKeyWithTag`: **[This function is resource-intensive]** Generates a DNSKEY with a specified KeyTag.

## License

This project is licensed under the [GPL-3.0 License](LICENSE).

---

For more information or support, please visit our [GitHub page](https://github.com/TochusC/godns).