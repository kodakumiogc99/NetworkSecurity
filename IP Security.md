---
tags: Computer Security
---



# IP Security

- Feature: It can encrypt and/or authenticate all traffic at the IP level

## Benefits

- When IPsec is implemented in a firewall or router, it provides strong
  security that can be applied to all traffic crossing the perimeter.
- IPsec in a firewall is resistant to bypass if all traffic from the
  outside must use IP and the firewall is the only means of entrance
  from the Internet into the organization.
- IPsec is below the transport layer (TCP, UDP) and so is transparent
  to applications.
  - There is no need to change software on a user or server system when
    IPsec is implemented in the firewall or router.
- IPsec can be transparent to end users
  - There is no need to train users on security mechanisms, issue keying
    material on a peruser basis, or revoke keying material when users
    leave the organization.
  - *Deying material* Key, code or authentication information in
    physical, electronic, or magnetic form. It includes key tapes and
    list, codes, authenticators, one-time pads, floppy disks, and
    magnetic tapes containing keys, plugs, keyed microcircuits,
    electronically generated key, etc.
- IPsec can provide security for individual users if needed
  - This is useful for offsite workers and for setting up a secure
    virtural subnetwork within an organization for sensitive applications

## Routing Applications

- IPsec can play a vital role in the routing architecture required for
  internetworking.
  - A router advertisement comes from an authorized router.
  - A router seeking to establish or maintain a neighbor relationship
    with a router in another routing domain is an authorized router.
  - A redirect message comes from the router to which the initial IP
    packet was sent.
  - A routing update is not forged.

## IPsec Documents

- Architecture
  - Covers the general concepts, security requirements, definitions,
    and mechanisms defining IPsec technology
  - The current specification is RFC4301, Security Architecture for
    the Internet Protocol
- Encapsulating Security Payload (ESP)
  - Consists of an encapsulating header and trailer used to provide
    encryption or combined encryption/ authentication
- Internet Key Exchange (IKE)
  - A collection of documents describing the key management schemes
    for use with IPsec.
  - The main specification is RFC5996, Internet Key Exchange Protocol,
    but there are a number of related RFCs
- Cryptographic algorithms
  - This category encompasses a large set of documents that define and
    describe cryptographic algorithms for encryption, message
    authentication, pseudorandom functions(PRFs), and cryptographic
    key exchange.
- Other
  - There are a variety of other IPsec-related RFCs, including those
    dealing with security policy and management information base (MIB)
    content.

## IPsec Srvices

- IPsec provides security services at the IP layer by enabling a system
  to:
  - Select required security protocols
  - Determine the algorithms(s) to use for the service(s)
  - Put in place any cryptographic keys required to provide the
    requested services.
- RFC 4301 lists the following services:
  - Access control
  - Connectionless integrity
  - Data origin authentication
  - Rejection of replayed packets (a form of partial sequence integrity)
  - Confidentiality (encryption)
  - Limited traffic flow confidentiality

## Transport and Tunnel Modes

- Transport Mode
  - Provides protection primarily for upper-layer protocols
  - Examples include a TCP or UDP segment or an ICMP packet
  - Typically used for end-to-end communication between two hosts
  - ESP in transport mode encrypts and optionally authenticates the IP
    payload but not the IP header
  - AH in transport mode authenticates the IP payload and selected
    portions of the IP header
- Tunnel Mode
  - Provides protection to the entire IP packet
  - Used when one or both ends of a security associatin (SA) are security
    gateway
  - A number of hosts on networks behind firewalls may engage in secure
    communications without implementing IPsec.
  - ESP in tunnel mode encrypts and optionally authenticates the entire
    inner IP packet, including the inner IP header.
  - AH in tunnel mode authenticates the entire inner IP packet and
    selected portions of the outer IP header.
   ![](./image/tunnel_node_format.png)

