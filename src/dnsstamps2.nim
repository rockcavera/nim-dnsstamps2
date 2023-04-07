## DNS Stamps is a specification that aims to encode all the data needed to connect to a DNS server
## in a single string (URI).
##
## The implementation is based on the specifications contained [here](https://dnscrypt.info/stamps-specifications/).
##
## Basic Use
## =========
## Creating a `StampObj` for Google's public DNS resolver and turning it into a string:
## ```nim
## import dnsstamps2
##
## let stamp = initPlainDNSStamp("8.8.8.8", Port(53), {StampProps.DNSSEC})
##
## echo toStamp(stamp)
## ```
##
## Parsing a DNS Stamp string to get all the specifications of a DNS resolver inside a `StampObj`:
## ```nim
## import dnsstamps2
##
## const strStamp = "sdns://AAEAAAAAAAAABzguOC44Ljg"
##
## let stamp = parseStamp(strStamp)
##
## echo stamp
## ```
import std/[base64, net, streams, strutils]

import pkg/stew/endians2

export Port

type
  StampProto* {.pure, size: 1.} = enum
    ## Is the protocol identifier for:
    PlainDNS = 0x00
      ## Plain DNS.
    DNSCrypt = 0x01
      ## DNSCrypt.
    DoH = 0x02
      ## DNS-over-HTTPS.
    DoT = 0x03
      ## DNS-over-TLS.
    DoQ = 0x04
      ## DNS-over-QUIC.
    ODoHTarget = 0x05
      ## Oblivious DoH target.
    DNSCryptRelay = 0x81
      ## Anonymized DNSCrypt relay.
    ODoHRelay = 0x85
      ## Oblivious DoH relay.

  StampProps* {.pure, size: 8.} = enum
    ## Informal properties about the resolver (server). It is a combination of the following values:
    DNSSEC # = 1
      ## The server supports DNSSEC.
    NoLog # = 2
      ## The server doesn’t keep logs.
    NoFilter # = 4
      ## The server doesn’t intentionally block domains.

  StampObj* = object
    ## Object with the information of a given resolver (server)
    address*: string
      ## It's the IP address. In some protocols it can contain the port, when the resolver (server)
      ## does not use the default port. IPv6 must be enclosed in square brackets [IPv6].
    props*: set[StampProps]
      ## It is a set with all the informal properties about the resolver (server).
    case protocol*: StampProto
      ## Is the resolver protocol being represented in the object.
    of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
      hashes*: seq[array[32, byte]]
        ## Is the SHA256 digest of one of the to be signed certificate found in the validation
        ## chain, typically the certificate used to sign the resolver’s certificate. Multiple hashes
        ## can be provided for seamless rotations.
      hostname*: string
        ## Is the server host name which will also be used as a SNI name. If the host name contains
        ## characters outside the URL-permitted range, these characters should be sent as-is,
        ## without any extra encoding (neither URL-encoded nor punycode). The port is optional and
        ## must be specified when it is not the default for the protocol.
      path*: string
        ## Is the absolute URI path. Only used in `DoH`, `ODoHTarget` and `ODoHRelay` protocols.
      bootstrapIps*: seq[string]
        ## Are IP addresses of recommended resolvers accessible over standard DNS in order to
        ## resolve hostname. This is optional, and clients can ignore this information.
    of StampProto.DNSCrypt:
      pk*: array[32, byte]
        ## Is the DNSCrypt provider’s Ed25519 public key.
      providerName*: string
        ## Is the DNSCrypt provider name. Must be prefixed with `2.dnscrypt-cert.`.
    else:
      discard

const
  dnsStampUriPrefix = "sdns://"
    ## URI prefix for DNSStamp.

# https://github.com/nim-lang/Nim/issues/6676
func `==`*(a, b: StampObj): bool =
  ## Returns `true` if `a` equals `b`.
  result = (a.protocol == b.protocol) and (a.address == b.address) and (a.props == b.props)
  case a.protocol
  of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
    result = result and (a.hashes == b.hashes) and (a.hostname == b.hostname) and
             (a.path == b.path) and (a.bootstrapIps == b.bootstrapIps)
  of StampProto.DNSCrypt:
    result = result and (a.pk == b.pk) and (a.providerName == b.providerName)
  else:
    discard

proc setAddress(ip: string, port: Port, standardPort: static[Port], address: var string) =
  ## Defines `address` with `ip` and `port`. If `ip` is IPv6, it will be enclosed in square
  ## brackets. If `port` is different from `standardPort`, `address` is suffixed with `:port`.
  ##
  ## **Note**
  ## - So that `port` is not added to `address`, use `standardPort = Port(0)`.
  let ipAddr = parseIpAddress(ip)

  case ipAddr.family
  of IpAddressFamily.IPv6:
    add(address, '[')
    add(address, ip)
    add(address, ']')
  of IpAddressFamily.IPv4:
    add(address, ip)

  when standardPort != Port(0):
    if port != standardPort:
      add(address, ':')
      add(address, $port)

proc setHostname(hostname: string, port: Port, standardPort: static[Port],
                 varHostname: var string) =
  ## Defines `varHostname` with `hostname` and `port`. If `port` is different from `standardPort`,
  ## `address` is suffixed with `:port`.
  add(varHostname, hostname)

  if port != standardPort:
    add(varHostname, ':')
    add(varHostname, $port)

proc initPlainDNSStamp*(ip: string, port: Port = Port(53), props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for Plain DNS (`StampProto.PlainDNS`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the server.
  ## - `port` is the server port.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: props,
    protocol: StampProto.PlainDNS)

  setAddress(ip, port, Port(53), result.address)

proc initDNSCryptStamp*(ip: string, providerName: string, pk: array[32, byte],
                        port: Port = Port(443), props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for DNSCrypt (`StampProto.DNSCrypt`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the server.
  ## - `providerName` is the DNSCrypt provider name.
  ## - `pk` is the provider's Ed25519 public key.
  ## - `port` is the server port.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: props,
    protocol: StampProto.DNSCrypt,
    pk: pk,
    providerName: providerName)

  setAddress(ip, port, Port(443), result.address)

  if not startsWith(providerName, "2.dnscrypt-cert."):
    result.providerName = "2.dnscrypt-cert." & providerName

proc initDoHStamp*(ip: string = "", hostname: string,  hashes: seq[array[32, byte]],
                   port: Port = Port(443), path: string = "/dns-query",
                   bootstrapIps: seq[string] = @[], props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for DNS-over-HTTPS (`StampProto.DoH`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the server. It can be an empty string, in which case the
  ##   `hostname` will be resolved to get the IP address of the server.
  ## - `hostname` is the hostname of the server.
  ## - `hashes` is a `seq` with one or more SHA256 digest of one of the TBS certificate found in the
  ##   validation chain, typically the certificate used to sign the resolver’s certificate.
  ## - `port` is the server port.
  ## - `path` is the absolute URI path.
  ## - `bootstrapIps` is a `seq` with recommended IP addresses to resolve `hostname` via standard
  ##   DNS. It is optional and can be empty.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(39), # IPv6
    props: props,
    protocol: StampProto.DoH,
    hashes: hashes,
    hostname: newStringOfCap(260), # 254 hostname + 6 :PORT
    path: path,
    bootstrapIps: bootstrapIps)

  if ip != "":
    setAddress(ip, port, Port(0), result.address)

  setHostname(hostname, port, Port(443), result.hostname)

proc initDoTStamp*(ip: string = "", hostname: string, hashes: seq[array[32, byte]],
                   port: Port = Port(443), bootstrapIps: seq[string] = @[],
                   props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for DNS-over-TLS (`StampProto.DoT`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the server. It can be an empty string, in which case the
  ##   `hostname` will be resolved to get the IP address of the server.
  ## - `hostname` is the hostname of the server.
  ## - `hashes` is a `seq` with one or more SHA256 digest of one of the TBS certificate found in the
  ##   validation chain, typically the certificate used to sign the resolver’s certificate.
  ## - `port` is the server port.
  ## - `bootstrapIps` is a `seq` with recommended IP addresses to resolve `hostname` via standard
  ##   DNS. It is optional and can be empty.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(39), # IPv6
    props: props,
    protocol: StampProto.DoT,
    hashes: hashes,
    hostname: newStringOfCap(260), # 254 hostname + 6 :PORT
    path: "",
    bootstrapIps: bootstrapIps)

  if ip != "":
    setAddress(ip, port, Port(0), result.address)

  setHostname(hostname, port, Port(443), result.hostname)

proc initDoQStamp*(ip: string = "", hostname: string, hashes: seq[array[32, byte]],
                   port: Port = Port(443), bootstrapIps: seq[string] = @[],
                   props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for DNS-over-QUIC (`StampProto.DoQ`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the server. It can be an empty string, in which case the
  ##   `hostname` will be resolved to get the IP address of the server.
  ## - `hostname` is the hostname of the server.
  ## - `hashes` is a `seq` with one or more SHA256 digest of one of the TBS certificate found in the
  ##   validation chain, typically the certificate used to sign the resolver’s certificate.
  ## - `port` is the server port.
  ## - `bootstrapIps` is a `seq` with recommended IP addresses to resolve `hostname` via standard
  ##   DNS. It is optional and can be empty.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(39), # IPv6
    props: props,
    protocol: StampProto.DoQ,
    hashes: hashes,
    hostname: newStringOfCap(260), # 254 hostname + 6 :PORT
    path: "",
    bootstrapIps: bootstrapIps)

  if ip != "":
    setAddress(ip, port, Port(0), result.address)

  setHostname(hostname, port, Port(443), result.hostname)

proc initODoHTargetStamp*(hostname: string, port: Port = Port(443), path: string = "/dns-query",
                          props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for Oblivious DoH target (`StampProto.ODoHTarget`).
  ##
  ## **Parameters**
  ## - `hostname` is the hostname of the server.
  ## - `port` is the server port.
  ## - `path` is the absolute URI path.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: "",
    props: props,
    protocol: StampProto.ODoHTarget,
    hashes: @[],
    hostname: newStringOfCap(260), # 254 hostname + 6 :PORT
    path: "",
    bootstrapIps: @[])

  setHostname(hostname, port, Port(443), result.hostname)

proc initDNSCryptRelayStamp*(ip: string, port: Port = Port(443)): StampObj =
  ## Initializes a `StampObj` for Anonymized DNSCrypt relay (`StampProto.DNSCryptRelay`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 of the relay server.
  ## - `port` is the relay server port.
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: {},
    protocol: StampProto.DNSCryptRelay)

  setAddress(ip, port, Port(443), result.address)

proc initODoHRelayStamp*(ip: string = "", hostname: string, hashes: seq[array[32, byte]],
                         port: Port = Port(443), path: string = "/dns-query",
                         bootstrapIps: seq[string] = @[], props: set[StampProps] = {}): StampObj =
  ## Initializes a `StampObj` for Oblivious DoH relay (`StampProto.ODoHRelay`).
  ##
  ## **Parameters**
  ## - `ip` is the IPv4 or IPv6 address of the relay server. It can be an empty string, in which case the
  ##   `hostname` will be resolved to get the IP address of the relay server.
  ## - `hostname` is the hostname of the relay server.
  ## - `hashes` is a `seq` with one or more SHA256 digest of one of the TBS certificate found in the
  ##   validation chain, typically the certificate used to sign the resolver’s certificate.
  ## - `port` is the relay server port.
  ## - `path` is the absolute URI path.
  ## - `bootstrapIps` is a `seq` with recommended IP addresses to resolve `hostname` via standard
  ##   DNS. It is optional and can be empty.
  ## - `props` is a `set` that represents informal properties about the resolver. See
  ##   `StampProps<#StampProps>`_.
  result = StampObj(
    address: newStringOfCap(39), # IPv6
    props: props,
    protocol: StampProto.ODoHRelay,
    hashes: hashes,
    hostname: newStringOfCap(260), # 254 hostname + 6 :PORT
    path: path,
    bootstrapIps: bootstrapIps)

  if ip != "":
    setAddress(ip, port, Port(0), result.address)

  setHostname(hostname, port, Port(443), result.hostname)

template writeLP[T: string|array[32, byte]](ss: StringStream, data: T) =
  ## Template to write a LP(`data`) in `ss`. For more information about LP(x), see the `DNS
  ## Stamps specification<https://dnscrypt.info/stamps-specifications/>`_.
  write(ss, uint8(len(data)))
  write(ss, data)

template writeVLP[T: string|array[32, byte]](ss: StringStream, seqT: seq[T]) =
  ## Template to write a VLP(`seqT`) in `ss`. For more information about VLP(x), see the `DNS
  ## Stamps specification<https://dnscrypt.info/stamps-specifications/>`_.
  for i in 0 ..< high(seqT):
    write(ss, uint8(len(seqT[i])) or 0x80'u8)
    write(ss, seqT[i])

  writeLP(ss, seqT[^1])

template toUint64(x: set[StampProps]): uint64 =
  ## Template to convert `set[StampProps]` to `uint64`.
  when nimvm:
    var ret = 0'u64

    for y in x:
      ret = ret or (1'u64 shl ord(y))

    ret
  else:
    cast[uint64](x)

proc toStamp*(stamp: StampObj): string =
  ## Turns `stamp` into its string representation.
  var ss = newStringStream()

  setLen(ss.data, 256)

  write(ss, uint8(ord(stamp.protocol)))

  if stamp.protocol != StampProto.DNSCryptRelay:
    write(ss, toLE(toUint64(stamp.props)))

  if stamp.protocol != StampProto.ODoHTarget:
    writeLP(ss, stamp.address)

  case stamp.protocol
  of StampProto.DNSCrypt:
    writeLP(ss, stamp.pk)

    writeLP(ss, stamp.providerName)
  of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
    if stamp.protocol != StampProto.ODoHTarget:
      writeVLP(ss, stamp.hashes)

    writeLP(ss, stamp.hostname)

    if stamp.protocol notin [StampProto.DoT, StampProto.DoQ]:
      writeLP(ss, stamp.path)

    if len(stamp.bootstrapIps) != 0 and stamp.protocol != StampProto.ODoHTarget:
      writeVLP(ss, stamp.bootstrapIps)
  else: # StampProto.PlainDNS, StampProto.DNSCryptRelay
    discard

  setLen(ss.data, getPosition(ss))

  result = dnsStampUriPrefix & encode(ss.data, true)

  close(ss)

  if result[^1] == '=':
    setLen(result, len(result) -% 1)
  if result[^1] == '=':
    setLen(result, len(result) -% 1)

template readLP(ss: StringStream): string =
  ## Template to read a LP(x) from `ss`. For more information about LP(x), see the `DNS Stamps
  ## specification<https://dnscrypt.info/stamps-specifications/>`_.
  let readLen = int(readUint8(ss))

  readStr(ss, readLen)

template readVLP[T: string|array[32, byte]](ss: StringStream, seqT: var seq[T]) =
  ## Template to read a VLP(x) from `ss` into `seqT`. For more information about VLP(x), see the `DNS Stamps
  ## specification<https://dnscrypt.info/stamps-specifications/>`_.
  var next = 0x80'u8

  while next == 0x80'u8:
    var readLen = readUint8(ss)

    next = next and readLen
    readLen = readLen and 0b01111111

    when T is string:
      add(seqT, readStr(ss, int(readLen)))
    else:
      var tmpArray: array[32, byte]

      read(ss, tmpArray)

      add(seqT, tmpArray)

template toSetStampProps(x: uint64): set[StampProps] =
  ## Template to convert a `uint64` to `set[StampProps]`.
  when nimvm:
    var
      r: set[StampProps]
      i = 0
      y = x

    while y != 0'u64:
      if (y and 1'u64) == 1'u64:
        incl(r, StampProps(i))

      i = i +% 1
      y = y shr 1

    r
  else:
    cast[set[StampProps]](x)

proc parseStamp*(uri: string): StampObj =
  ## Parses a string representation of a DNS Stamp contained in `uri`.
  if not startsWith(uri, dnsStampUriPrefix):
    raise newException(ValueError, "Is Not a valid URI for DNS Stamp")

  var
    ss = newStringStream(decode(uri[len(dnsStampUriPrefix)..^1]))
    props: set[StampProps]
    address: string

  let protocol = StampProto(readUint8(ss))

  if protocol != StampProto.DNSCryptRelay:
    props = toSetStampProps(fromLE(readUint64(ss)))

  if protocol != StampProto.ODoHTarget:
    address = readLP(ss)

  case protocol
  of StampProto.DNSCrypt:
    var pk: array[32, byte]

    discard readUint8(ss) # will always be 32
    discard readData(ss, addr pk, 32)

    let providerName = readLP(ss)

    result = StampObj(address: address, props: props, protocol: protocol, pk: pk,
                      providerName: providerName)
  of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
    var
      hashes: seq[array[32, byte]]
      path: string
      bootstrapIps: seq[string]

    if protocol != StampProto.ODoHTarget:
      readVLP(ss, hashes)

    let hostname = readLP(ss)

    if protocol notin [StampProto.DoT, StampProto.DoQ]:
      path = readLP(ss)

    if not(atEnd(ss)) and (protocol != StampProto.ODoHTarget):
      readVLP(ss, bootstrapIps)

    result = StampObj(address: address, props: props, protocol: protocol, hashes: hashes,
                      hostname: hostname, path: path, bootstrapIps: bootstrapIps)
  else: # StampProto.PlainDNS, StampProto.DNSCryptRelay
    result = StampObj(address: address, props: props, protocol: protocol)

  close(ss)
