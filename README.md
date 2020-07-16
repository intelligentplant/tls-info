﻿# tls-info

A simple command line tool for displaying information about a TLS connection. The tool is largely based on [this Stack Overflow answer](https://stackoverflow.com/a/48675492). 


## Usage

Run `tls-info <host name> [<host name 2> ... <host name N>]`. For each host name provided, the tool will attempt to create a connection using a `TcpClient` and an `SslStream`, and then display information about the selected cipher suite and the remote server certificate. Where no port is specified in the host name, port 443 will be used.


## Examples

Display information for Google and LinkedId:

	tls-info www.google.com www.linkedin.com


Display information for localhost on a specific port:

	tls-info localhost:43889


Display information for specific IPv4 and v6 addresses:

	tls-info 2002:0a00:0001::0a00:0001:44321 10.0.0.1:44321
