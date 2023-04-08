DNS Stamps package for Nim.

DNS Stamps is a specification that aims to encode all the data needed to access a DNS server in a single string (URI).

The implementation is based on the specifications contained [here](https://dnscrypt.info/stamps-specifications/).

# Install
`nimble install https://github.com/rockcavera/nim-dnsstamps2.git`

# Basic Use
Creating a `StampObj` for Google's public DNS resolver and turning it into a string:
```nim
import dnsstamps2

let stamp = initPlainDNSStamp("8.8.8.8", Port(53), {StampProps.DNSSEC})

echo toStamp(stamp)
```

Parsing a DNS Stamp string to get all the specifications of a DNS resolver inside a `StampObj`:
```nim
import dnsstamps2

const strStamp = "sdns://AAEAAAAAAAAABzguOC44Ljg"

let stamp = parseStamp(strStamp)

echo stamp
```

# Documentation
https://rockcavera.github.io/nim-dnsstamps2/dnsstamps2.html
