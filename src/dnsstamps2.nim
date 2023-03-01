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

proc setAddress(ip: string, port: Port, standardPort: Port, address: var string) =
  let ipAddr = parseIpAddress(ip)

  case ipAddr.family
  of IpAddressFamily.IPv6:
    add(address, '[')
    add(address, ip)
    add(address, ']')
  of IpAddressFamily.IPv4:
    add(address, ip)

  if port != standardPort:
    add(address, ':')
    add(address, $port)

proc initPlainDNS*(ip: string, port: Port, props: set[StampProps]): StampObj =
  result = StampObj(
    address: newStringOfCap(47),
    props: props,
    protocol: StampProto.PlainDNS)

  setAddress(ip, port, Port(53), result.address)

proc initDNSCryptStamp*(ip: string, port: Port, providerName: string, pk: array[32, byte],
                        props: set[StampProps]): StampObj =
  result = StampObj(
    address: newStringOfCap(47),
    props: props,
    protocol: StampProto.DNSCrypt,
    pk: pk,
    providerName: providerName)

  setAddress(ip, port, Port(443), result.address)

  if not startsWith(providerName, "2.dnscrypt-cert."):
    result.providerName = "2.dnscrypt-cert." & providerName

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

when isMainModule:
  let a = initDNSCryptStamp("2620:0:ccc::2", Port(443), "opendns.com", [0xb7.byte, 0x35, 0x11, 0x40, 0x20, 0x6f, 0x22, 0x5d, 0x3e, 0x2b, 0xd8, 0x22, 0xd7, 0xfd, 0x69, 0x1e, 0xa1, 0xc3, 0x3c, 0xc8, 0xd6, 0x66, 0x8d, 0x0c, 0xbe, 0x04, 0xbf, 0xab, 0xca, 0x43, 0xfb, 0x79], {DNSSEC})

  doAssert(toStamp(a) == "sdns://AQEAAAAAAAAAD1syNjIwOjA6Y2NjOjoyXSC3NRFAIG8iXT4r2CLX_WkeocM8yNZmjQy-BL-rykP7eRsyLmRuc2NyeXB0LWNlcnQub3BlbmRucy5jb20")

  let b = parseStamp("sdns://AQEAAAAAAAAAD1syNjIwOjA6Y2NjOjoyXSC3NRFAIG8iXT4r2CLX_WkeocM8yNZmjQy-BL-rykP7eRsyLmRuc2NyeXB0LWNlcnQub3BlbmRucy5jb20")

  let c = initPlainDNS("8.8.8.8", Port(53), {DNSSEC})

  doAssert(toStamp(c) == "sdns://AAEAAAAAAAAABzguOC44Ljg")

  let d = parseStamp("sdns://AgUAAAAAAAAABzguOC44LjigHvYkz_9ea9O63fP92_3qVlRn43cpncfuZnUWbzAMwbmgdoAkR6AZkxo_AEMExT_cbBssN43Evo9zs5_ZyWnftEUgalBisNF41VbxY7E7Gw8ZQ10CWIKRzHVYnf7m6xHI1cMKZG5zLmdvb2dsZQovZG5zLXF1ZXJ5")
  echo d
