# Go File Server

This is a simple file server written in Go. Have you ever wanted to transfer 
files between computers on the same LAN? Simply run this program, give it a 
directory of files to serve, and navigate to the IP address and port number
in the other computer's web browser to download, upload, or delete files. 

Note, folders can only be deleted if empty.

**WARNING**

This program does not have TLS or authentication yet so anyone on the LAN
or network can download, delete, or manipulate your files as well as upload
malicious files to the computer running this program. Only use on a secure 
or trusted network. Adding TLS and simple authentication are in the works.

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


**Mini**

The mini directory contains a simplified version of this program that is a
single Go file. The mini version does not depend on templates or CSS files. 
It operates the same way, it is just more portable. 

cd into mini directory

    cd ./mini

Build it

    go build ./mini.go

Get help

    ./mini --help

Or start serving files

    ./mini /home/user/files

**Contributing**

Pull requests, new feature suggestions, and bug reports/issues are
welcome.


**License**

This project is licensed under the 3-Clause BSD License also known as the
*"New BSD License"* or the *"Modified BSD License"*. A copy of the license
can be found in the LICENSE file. A copy can also be found at the
[Open Source Institute](https://opensource.org/licenses/BSD-3-Clause)