# https://dnscrypt.info/stamps-specifications/

# "sdns://" || base64url(0x00 || props || LP(addr [:port]))
# "sdns://" || base64url(0x01 || props || LP(addr [:port]) || LP(pk) || LP(providerName))
# "sdns://" || base64url(0x02 || props || LP(addr) || VLP(hash1, hash2, ...hashn) || LP(hostname [:port]) || LP(path) [ || VLP(bootstrap_ip1, bootstrap_ip2, ...bootstrap_ipn) ])
# "sdns://" || base64url(0x03 || props || LP(addr) || VLP(hash1, hash2, ...hashn) || LP(hostname [:port]) ||          [ || VLP(bootstrap_ip1, bootstrap_ip2, ...bootstrap_ipn) ])
# "sdns://" || base64url(0x04 || props || LP(addr) || VLP(hash1, hash2, ...hashn) || LP(hostname [:port]) ||          [ || VLP(bootstrap_ip1, bootstrap_ip2, ...bootstrap_ipn) ])
# "sdns://" || base64url(0x05 || props ||                                            LP(hostname [:port]) || LP(path))
# "sdns://" || base64url(0x81 ||          LP(addr))
# "sdns://" || base64url(0x85 || props || LP(addr) || VLP(hash1, hash2, ...hashn) || LP(hostname [:port]) || LP(path) [ || VLP(bootstrap_ip1, bootstrap_ip2, ...bootstrap_ipn) ])

import std/[base64, net, streams, strutils]

import pkg/stew/endians2

export Port

type
  StampProto* {.pure, size: 1.} = enum
    PlainDNS = 0x00 ## Plain DNS
    DNSCrypt = 0x01 ## DNSCrypt
    DoH = 0x02 ## DNS-over-HTTPS
    DoT = 0x03 ## DNS-over-TLS
    DoQ = 0x04 ## DNS-over-QUIC
    ODoHTarget = 0x05 ## Oblivious DoH target
    DNSCryptRelay = 0x81 ## Anonymized DNSCrypt relay
    ODoHRelay = 0x85 ## Oblivious DoH relay

  StampProps* {.pure, size: 8.} = enum
    DNSSEC # = 1
    NoLog # = 2
    NoFilter # = 4

  StampObj* = object
    address*: string
    props*: set[StampProps]
    case protocol*: StampProto
    of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
      hashes*: seq[string]
      hostname*: string
      path*: string
      bootstrapIps*: seq[string]
    of StampProto.DNSCrypt:
      pk*: array[32, byte]
      providerName*: string
    else:
      discard

const
  dnsStampUri = "sdns://"

# https://github.com/nim-lang/Nim/issues/6676
func `==`*(a, b: StampObj): bool =
  result = true
  if a.protocol != b.protocol:
    result = false
  elif a.address != b.address:
    result = false
  elif a.props != b.props:
    result = false
  else:
    case a.protocol
    of StampProto.DoH, StampProto.DoT, StampProto.DoQ, StampProto.ODoHTarget, StampProto.ODoHRelay:
      result = (a.hashes == b.hashes) and (a.hostname == b.hostname) and (a.path == b.path) and (a.bootstrapIps == b.bootstrapIps)
    of StampProto.DNSCrypt:
      result = (a.pk == b.pk) and (a.providerName == b.providerName)
    else:
      discard

proc setAddress(ip: string, port: Port, standardPort: static[Port], address: var string) =
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
  add(varHostname, hostname)

  if port != standardPort:
    add(varHostname, ':')
    add(varHostname, $port)

proc initPlainDNSStamp*(ip: string, port: Port, props: set[StampProps] = {}): StampObj =
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: props,
    protocol: StampProto.PlainDNS)

  setAddress(ip, port, Port(53), result.address)

proc initDNSCryptStamp*(ip: string, port: Port = Port(443), providerName: string,
                        pk: array[32, byte], props: set[StampProps] = {}): StampObj =
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: props,
    protocol: StampProto.DNSCrypt,
    pk: pk,
    providerName: providerName)

  setAddress(ip, port, Port(443), result.address)

  if not startsWith(providerName, "2.dnscrypt-cert."):
    result.providerName = "2.dnscrypt-cert." & providerName

proc initDoHStamp*(ip: string = "", hostname: string, port: Port = Port(443), hashes: seq[string],
                   path: string = "/dns-query", bootstrapIps: seq[string] = @[],
                   props: set[StampProps] = {}): StampObj =
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

proc initDoTStamp*(ip: string = "", hostname: string, port: Port = Port(443), hashes: seq[string],
                   bootstrapIps: seq[string] = @[], props: set[StampProps] = {}): StampObj =
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

proc initDoQStamp*(ip: string = "", hostname: string, port: Port = Port(443), hashes: seq[string],
                   bootstrapIps: seq[string] = @[], props: set[StampProps] = {}): StampObj =
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
  result = StampObj(
    address: newStringOfCap(47), # [IPv6]:PORT
    props: {},
    protocol: StampProto.DNSCryptRelay)

  setAddress(ip, port, Port(443), result.address)

proc initODoHRelayStamp*(ip: string = "", hostname: string, port: Port = Port(443),
                         hashes: seq[string], path: string = "/dns-query",
                         bootstrapIps: seq[string] = @[], props: set[StampProps] = {}): StampObj =
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

template writeLP(ss: StringStream, str: string) =
  write(ss, uint8(len(str)))
  write(ss, str)

template writeVLP(ss: StringStream, seqStr: seq[string]) =
  for i in 0 ..< high(seqStr):
    write(ss, uint8(len(seqStr[i])) or 0x80'u8)
    write(ss, seqStr[i])

  writeLP(ss, seqStr[^1])

template toUint64(x: set[StampProps]): uint64 =
  when nimvm:
    var r = 0'u64

    for y in x:
      r = r or (1'u64 shl ord(y))

    r
  else:
    cast[uint64](x)

proc toStamp*(stamp: StampObj): string =
  var ss = newStringStream()

  setLen(ss.data, 256)

  write(ss, uint8(ord(stamp.protocol)))

  if stamp.protocol != StampProto.DNSCryptRelay:
    write(ss, toLE(toUint64(stamp.props)))

  if stamp.protocol != StampProto.ODoHTarget:
    writeLP(ss, stamp.address)

  case stamp.protocol
  of StampProto.DNSCrypt:
    write(ss, 32'u8)
    write(ss, stamp.pk)

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

  result = dnsStampUri & encode(ss.data, true)

  close(ss)

  if result[^1] == '=':
    setLen(result, len(result) -% 1)
  if result[^1] == '=':
    setLen(result, len(result) -% 1)

template readLP(ss: StringStream): string =
  let readLen = int(readUint8(ss))

  readStr(ss, readLen)

template readVLP(ss: StringStream, seqStr: var seq[string]) =
  var next = 0x80'u8

  while next == 0x80'u8:
    var readLen = readUint8(ss)

    next = next and readLen
    readLen = readLen and 0b01111111

    add(seqStr, readStr(ss, int(readLen)))

template toSetStampProps(x: uint64): set[StampProps] =
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
  if not startsWith(uri, dnsStampUri):
    raise newException(ValueError, "Is Not a valid URI for DNS Stamp")

  var
    ss = newStringStream(decode(uri[len(dnsStampUri)..^1]))
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
      hashes: seq[string]
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
