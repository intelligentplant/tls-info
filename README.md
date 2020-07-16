# tls-info

A simple command line tool for displaying information about a TLS connection. The tool is largely based on [this Stack Overflow answer](https://stackoverflow.com/a/48675492). 


## Building the Tool

Run `dotnet build` from the command line. This will build executables for .NET Framework and .NET Core.


## Usage

Run `tls-info <host name> [<host name 2> ... <host name N>]`. For each host name provided, the tool will attempt to create a connection using a `TcpClient` and an `SslStream`, and then display information about the selected cipher suite and the remote server certificate. Where no port is specified in the host name, port 443 will be used.


## Examples

Display information for Google and LinkedIn:

	tls-info www.google.com www.linkedin.com


Display information for localhost on a specific port:

	tls-info localhost:43889


Display information for specific IPv4 and v6 addresses:

	tls-info 2002:0a00:0001::0a00:0001:44321 10.0.0.1:44321


Example output:

```
=============================== localhost:48189 ===============================

Resolved Host Name: localhost
TLS Version: Tls12
Key Exchange Algorithm: Ecdhe
Cipher Algorithm: Aes256
Hash Algorithm: Sha384
Certificate:

[Subject]
  CN=localhost

[Issuer]
  CN=localhost

[Serial Number]
  0123456789ABCDEF01

[Not Before]
  01/01/2020 13:48:42

[Not After]
  01/01/2021 13:48:42

[Thumbprint]
  FEDCBA9876543210FEDCBA9876543210FEDCBA98
```
