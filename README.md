# Beef-Net

BeefLang networking library, based on [lNet](https://github.com/almindor/lnet)

## Dependencies

Beef-Net relies on [Beef-OpenSSL](https://github.com/thibmo/Beef-OpenSSL) for handling SSL-related operations.

## Quick Start *(using Beef IDE)*

1. **Download** Beef-Net and copy it into BeefLibs inside your Beef IDE root directory.
2. In the Beef IDE, add Beef-OpenSSL to your workspace (Add From Installed)
3. In the Beef IDE, add Beef-Net to your workspace (Add From Installed)
4. In the Beef IDE, add Beef-Net to your project (Properties > Dependencies)
5. Have fun!

## Where is the HTTP functionality?

I moved the HTTP socket, client, and server to https://github.com/tomwjerry/Beef-Http-Server/tree/main

In the future, FTP, SMTP and Telnet will also be in own repos. So that one can download the desired
networking service without needing the others. Beef-Net will be required for those, and most likely Beef-OpenSSL.

I will drop the Beef-OpenSSL from this library in the future, but as with most networking, SSL is desired...

## Examples

- [FTP Client](https://github.com/thibmo/Beef-Net/tree/main/Examples/FtpClient)
- [SMTP Client](https://github.com/thibmo/Beef-Net/tree/main/Examples/SmtpClient)
- [Telnet Client](https://github.com/thibmo/Beef-Net/tree/main/Examples/Telnet)
