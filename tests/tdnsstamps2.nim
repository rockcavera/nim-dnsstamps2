import std/unittest

import dnsstamps2

suite "PlainDNS":
  test "IPv4":
    const sdnsUri = "sdns://AAEAAAAAAAAABzguOC44Ljg"

    let
      a = initPlainDNSStamp("8.8.8.8", Port(53), {StampProps.DNSSEC})
      b = StampObj(address: "8.8.8.8", props: {StampProps.DNSSEC}, protocol: StampProto.PlainDNS)

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

  test "IPv6":
    const sdnsUri = "sdns://AAEAAAAAAAAAFlsyMDAxOjQ4NjA6NDg2MDo6ODg4OF0"

    let
      a = initPlainDNSStamp("2001:4860:4860::8888", Port(53), {StampProps.DNSSEC})
      b = StampObj(address: "[2001:4860:4860::8888]", props: {StampProps.DNSSEC}, protocol: StampProto.PlainDNS)

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

suite "DNSCrypt":
  test "IPv4":
    const sdnsUri = "sdns://AQcAAAAAAAAAEzE2NC42OC4xMjEuMTYyOjQ0NDMgHtKNfXpUMzPyLnXK8DauHpWm1Rqhz7LqwBBmSzdY9BIcMi5kbnNjcnlwdC1jZXJ0LnByeXY4Ym9pLm9yZw"

    let
      pk = [0x1e.byte, 0xd2, 0x8d, 0x7d, 0x7a, 0x54, 0x33, 0x33, 0xf2, 0x2e, 0x75, 0xca, 0xf0, 0x36, 0xae, 0x1e, 0x95, 0xa6, 0xd5, 0x1a, 0xa1, 0xcf, 0xb2, 0xea, 0xc0, 0x10, 0x66, 0x4b, 0x37, 0x58, 0xf4, 0x12]
      a = initDNSCryptStamp("164.68.121.162", "pryv8boi.org", pk, Port(4443), {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog})
      b = StampObj(address: "164.68.121.162:4443", props: {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog}, protocol: StampProto.DNSCrypt, pk: pk, providerName: "2.dnscrypt-cert.pryv8boi.org")

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

  test "IPv6":
    const sdnsUri = "sdns://AQcAAAAAAAAAKFsyMDAxOjE5ZjA6NzQwMjoxNTc0OjU0MDA6MmZmOmZlNjY6MmNmZl0g7Uk9jOrXkGZPBjxHt5WaI2ktfJA2PJ5DzLWRe-W0HuUdMi5kbnNjcnlwdC1jZXJ0LnYuZG5zY3J5cHQudWs"

    let
      pk = [0xed.byte, 0x49, 0x3d, 0x8c, 0xea, 0xd7, 0x90, 0x66, 0x4f, 0x06, 0x3c, 0x47, 0xb7, 0x95, 0x9a, 0x23, 0x69, 0x2d, 0x7c, 0x90, 0x36, 0x3c, 0x9e, 0x43, 0xcc, 0xb5, 0x91, 0x7b, 0xe5, 0xb4, 0x1e, 0xe5]
      a = initDNSCryptStamp("2001:19f0:7402:1574:5400:2ff:fe66:2cff", "v.dnscrypt.uk", pk, Port(443), {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog})
      b = StampObj(address: "[2001:19f0:7402:1574:5400:2ff:fe66:2cff]", props: {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog}, protocol: StampProto.DNSCrypt, pk: pk, providerName: "2.dnscrypt-cert.v.dnscrypt.uk")

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

suite "DoH":
  test "IPv4":
    const sdnsUri = "sdns://AgIAAAAAAAAADjExNi4yMDIuMTc2LjI2oMwQYNOcgym2K2-8fQ1t-TCYabmB5-Y5LVzY-kCPTYDmIEROvWe7g_iAezkh6TiskXi4gr1QqtsRIx8ETPXwjffOD2RvaC5saWJyZWRucy5ncgQvYWRz"

    let
      hashes = @[[0xcc.byte, 0x10, 0x60, 0xd3, 0x9c, 0x83, 0x29, 0xb6, 0x2b, 0x6f, 0xbc, 0x7d, 0x0d, 0x6d, 0xf9, 0x30, 0x98, 0x69, 0xb9, 0x81, 0xe7, 0xe6, 0x39, 0x2d, 0x5c, 0xd8, 0xfa, 0x40, 0x8f, 0x4d, 0x80, 0xe6],
                 [0x44.byte, 0x4e, 0xbd, 0x67, 0xbb, 0x83, 0xf8, 0x80, 0x7b, 0x39, 0x21, 0xe9, 0x38, 0xac, 0x91, 0x78, 0xb8, 0x82, 0xbd, 0x50, 0xaa, 0xdb, 0x11, 0x23, 0x1f, 0x04, 0x4c, 0xf5, 0xf0, 0x8d, 0xf7, 0xce]]
      a = initDoHStamp("116.202.176.26", "doh.libredns.gr", hashes, Port(443), "/ads", @[], {StampProps.NoLog})
      b = StampObj(address: "116.202.176.26", props: {StampProps.NoLog}, protocol: StampProto.DoH, hashes: hashes, hostname: "doh.libredns.gr", path: "/ads", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

  test "IPv6":
    const sdnsUri = "sdns://AgUAAAAAAAAAFlsyMDAxOjQ4NjA6NDg2MDo6ODg4OF2gHvYkz_9ea9O63fP92_3qVlRn43cpncfuZnUWbzAMwbmgdoAkR6AZkxo_AEMExT_cbBssN43Evo9zs5_ZyWnftEUgalBisNF41VbxY7E7Gw8ZQ10CWIKRzHVYnf7m6xHI1cMKZG5zLmdvb2dsZQovZG5zLXF1ZXJ5"

    let
      hashes = @[[0x1e.byte, 0xf6, 0x24, 0xcf, 0xff, 0x5e, 0x6b, 0xd3, 0xba, 0xdd, 0xf3, 0xfd, 0xdb, 0xfd, 0xea, 0x56, 0x54, 0x67, 0xe3, 0x77, 0x29, 0x9d, 0xc7, 0xee, 0x66, 0x75, 0x16, 0x6f, 0x30, 0x0c, 0xc1, 0xb9],
                 [0x76.byte, 0x80, 0x24, 0x47, 0xa0, 0x19, 0x93, 0x1a, 0x3f, 0x00, 0x43, 0x04, 0xc5, 0x3f, 0xdc, 0x6c, 0x1b, 0x2c, 0x37, 0x8d, 0xc4, 0xbe, 0x8f, 0x73, 0xb3, 0x9f, 0xd9, 0xc9, 0x69, 0xdf, 0xb4, 0x45],
                 [0x6a.byte, 0x50, 0x62, 0xb0, 0xd1, 0x78, 0xd5, 0x56, 0xf1, 0x63, 0xb1, 0x3b, 0x1b, 0x0f, 0x19, 0x43, 0x5d, 0x02, 0x58, 0x82, 0x91, 0xcc, 0x75, 0x58, 0x9d, 0xfe, 0xe6, 0xeb, 0x11, 0xc8, 0xd5, 0xc3]]
      a = initDoHStamp("2001:4860:4860::8888", "dns.google", hashes, Port(443), "/dns-query", @[], {StampProps.DNSSEC, StampProps.NoFilter})
      b = StampObj(address: "[2001:4860:4860::8888]", props: {StampProps.DNSSEC, StampProps.NoFilter}, protocol: StampProto.DoH, hashes: hashes, hostname: "dns.google", path: "/dns-query", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

suite "DoT":
  test "IPv4":
    const sdnsUri = "sdns://AwcAAAAAAAAABzEuMS4xLjGgGP8Knf7qBae-aIfythytMbYnL-yowaWVeD6MoLHkVRgge0IRz5Tio3GA1Xs4fUVWmH1xHDiH2dMbVtCBSkOIdqMTb25lLm9uZS5vbmUub25lOjg1Mw"

    let
      hashes = @[[24.byte, 255, 10, 157, 254, 234, 5, 167, 190, 104, 135, 242, 182, 28, 173, 49, 182, 39, 47, 236, 168, 193, 165, 149, 120, 62, 140, 160, 177, 228, 85, 24],
                 [123.byte, 66, 17, 207, 148, 226, 163, 113, 128, 213, 123, 56, 125, 69, 86, 152, 125, 113, 28, 56, 135, 217, 211, 27, 86, 208, 129, 74, 67, 136, 118, 163]]
      a = initDoTStamp("1.1.1.1", "one.one.one.one", hashes, Port(853), @[], {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog})
      b = StampObj(address: "1.1.1.1", props: {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog}, protocol: StampProto.DoT, hashes: hashes, hostname: "one.one.one.one:853", path: "", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

  test "IPv6":
    const sdnsUri = "sdns://AwUAAAAAAAAAFlsyMDAxOjQ4NjA6NDg2MDo6ODg4OF2geiv9fT9AnC-8N5JMeZHiPJ9zBnH26_USZOghYSWM4vigzCTnfLwLKbS9S2sbp-uFz4KZOocFvXxkV06Ce9O5M2wghxqRlPTu1bMS_0DITB1SSu0vd4u_8l8TjPgfaAp63GcOZG5zLmdvb2dsZTo4NTM"

    let
      hashes = @[[0x7a.byte, 0x2b, 0xfd, 0x7d, 0x3f, 0x40, 0x9c, 0x2f, 0xbc, 0x37, 0x92, 0x4c, 0x79, 0x91, 0xe2, 0x3c, 0x9f, 0x73, 0x06, 0x71, 0xf6, 0xeb, 0xf5, 0x12, 0x64, 0xe8, 0x21, 0x61, 0x25, 0x8c, 0xe2, 0xf8],
                 [0xcc.byte, 0x24, 0xe7, 0x7c, 0xbc, 0x0b, 0x29, 0xb4, 0xbd, 0x4b, 0x6b, 0x1b, 0xa7, 0xeb, 0x85, 0xcf, 0x82, 0x99, 0x3a, 0x87, 0x05, 0xbd, 0x7c, 0x64, 0x57, 0x4e, 0x82, 0x7b, 0xd3, 0xb9, 0x33, 0x6c],
                 [0x87.byte, 0x1a, 0x91, 0x94, 0xf4, 0xee, 0xd5, 0xb3, 0x12, 0xff, 0x40, 0xc8, 0x4c, 0x1d, 0x52, 0x4a, 0xed, 0x2f, 0x77, 0x8b, 0xbf, 0xf2, 0x5f, 0x13, 0x8c, 0xf8, 0x1f, 0x68, 0x0a, 0x7a, 0xdc, 0x67]]
      a = initDoTStamp("2001:4860:4860::8888", "dns.google", hashes, Port(853), @[], {StampProps.DNSSEC, StampProps.NoFilter})
      b = StampObj(address: "[2001:4860:4860::8888]", props: {StampProps.DNSSEC, StampProps.NoFilter}, protocol: StampProto.DoT, hashes: hashes, hostname: "dns.google:853", path: "", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

suite "DoQ":
  test "IPv4":
    const sdnsUri = "sdns://BAcAAAAAAAAADTk0LjE0MC4xNC4xNDAgmjo09yfeubylEAPZzpw5-PJ92cUkKQHCurGkTmNaAhkeZG5zLXVuZmlsdGVyZWQuYWRndWFyZC5jb206ODUz"

    let
      hashes = @[[0x9a.byte, 0x3a, 0x34, 0xf7, 0x27, 0xde, 0xb9, 0xbc, 0xa5, 0x10, 0x03, 0xd9, 0xce, 0x9c, 0x39, 0xf8, 0xf2, 0x7d, 0xd9, 0xc5, 0x24, 0x29, 0x01, 0xc2, 0xba, 0xb1, 0xa4, 0x4e, 0x63, 0x5a, 0x02, 0x19]]
      a = initDoQStamp("94.140.14.140", "dns-unfiltered.adguard.com", hashes, Port(853), @[], {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog})
      b = StampObj(address: "94.140.14.140", props: {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog}, protocol: StampProto.DoQ, hashes: hashes, hostname: "dns-unfiltered.adguard.com:853", path: "", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b

  test "IPv6":
    const sdnsUri = "sdns://BAcAAAAAAAAAEVsyYTEwOjUwYzA6OjE6ZmZdIJo6NPcn3rm8pRAD2c6cOfjyfdnFJCkBwrqxpE5jWgIZHmRucy11bmZpbHRlcmVkLmFkZ3VhcmQuY29tOjg1Mw"

    let
      hashes = @[[0x9a.byte, 0x3a, 0x34, 0xf7, 0x27, 0xde, 0xb9, 0xbc, 0xa5, 0x10, 0x03, 0xd9, 0xce, 0x9c, 0x39, 0xf8, 0xf2, 0x7d, 0xd9, 0xc5, 0x24, 0x29, 0x01, 0xc2, 0xba, 0xb1, 0xa4, 0x4e, 0x63, 0x5a, 0x02, 0x19]]
      a = initDoQStamp("2a10:50c0::1:ff", "dns-unfiltered.adguard.com", hashes, Port(853), @[], {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog})
      b = StampObj(address: "[2a10:50c0::1:ff]", props: {StampProps.DNSSEC, StampProps.NoFilter, StampProps.NoLog}, protocol: StampProto.DoQ, hashes: hashes, hostname: "dns-unfiltered.adguard.com:853", path: "", bootstrapIps: @[])

    check a == b
    check toStamp(a) == sdnsUri
    check parseStamp(sdnsUri) == b
