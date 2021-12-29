# Go File Server

This is a simple file server written in Go. Have you ever wanted to transfer 
files between computers on the same LAN? Simply run this program, give it a 
directory of files to serve, and navigate to the IP address and port number
in the other computer's web browser to download, upload, or delete files. 

The goal of this program is to be as portable and to use as few
external dependencies as possible. I wanted to use only the standard library
for this program. I also understand that this program could be cleaner if
broken up into multiple files, but I wanted it to keep it in a single source
file to make it easier to copy or send to other computers. 

Note, folders can only be deleted if empty.

**WARNING**

While this server supports TLS and basic authentication, it may not be perfect.
I would recommend only using it on a secure or trusted network. Pick a good 
password when using basic authentication. Basic authentication is useless 
without TLS enabled too! If possible, use your own TLS certs instead of 
auto-generating self-signed certificates.

**Defaults**

Default settings are to serve on all public IP's (0.0.0.0) on port 8080.
Can be changed with command line arguments


**Usage**

Install Go and download this repository

Unzip the files and change into the cmd directory

    cd ./cmd

Build the program

    go build main.go

Run the program with --help to see available options

    ./main --help

Serve up a directory of files

    ./main /home/user/files

Generate self-signed TLS certs and serve directory

    ./main -t /home/user/files

Set up basic auth with already generated TLS certs. Basic auth will 
interactively prompt for a password to avoid storing a password 
in .bash_history or other command line logs. 

    ./main -c cert.pem -k key.pem -u Bob /home/user/files

**Contributing**

Pull requests, new feature suggestions, and bug reports/issues are
welcome.


**License**

This project is licensed under the 3-Clause BSD License also known as the
*"New BSD License"* or the *"Modified BSD License"*. A copy of the license
can be found in the LICENSE file. A copy can also be found at the
[Open Source Institute](https://opensource.org/licenses/BSD-3-Clause)