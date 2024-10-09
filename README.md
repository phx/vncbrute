![screenshot](./screenshot.png?raw=true)

# vncbrute

![vncbrute](./image.webp?raw=true)

This is a VNC brute force utility that only uses the standard Go libraries and was written entirely by GPT-4o and o1-preview. I did not write a single line of this code. 

With 100 concurrent workers and a 2 second timeout, it takes about 7 minutes to execute a successful dictionary attack against a VNC server listening on localhost, using a list of 1,000 passwords.

I am a developer.  I am a coder.  I spent a lot of time on this, and yes, it felt like coding.  Just different.  It is much, much faster.  Artificial Intelligence is the best dev team I never wanted to be a part of.
This is the future of coding and development.  Pretty soon everyone will be a developer, but the best ones will have already been developers before the AI boom.

GPT-4o made this possible, and I don't think I would have kept at it if o1-preview hadn't been there to help out with a couple of sticky situations.

With GPT-4o, on this date of October 8th, 2024, the future is here, and this is what it looks like.

The majority of my time was spent copying, pasting, and compiling.  Within the next few months, I believe tools like [Open Interpreter](https://github.com/OpenInterpreter/open-interpreter) will be able to automate 100% of the troubleshooting to the point that it just keeps correcting itself until you achieve the desired result. It's already 99.9% there for things just like this.

Previously, the majority of my time was spent reading documentation in order to troubleshoot functionality. This program implements the VNC protocol by itself without any helper libraries. I did not have to learn the protocol.

People just don't understand that this is the gamechanger. Prior to this point in time, if I wanted to decorate my house by hanging a clock on the wall, I would have to learn how clocks work. Now I can put clocks anywhere I want them and all I
need to know is how to tell time. The scaleability offered by outsourcing the low level knowledge to artificial intelligence, opens up a whole new world of possibilities for society. This is very dangerous. But it is also very exciting, and I'm
hoping the good will outweigh the bad.

## Installation:

The following command will install the version that looks prettier in the terminal but also relies on a third party library:

```
go install github.com/phx/vncbrute
```

## Install without dependencies:

```
git clone https://github.com/phx/vncbrute
cd vncbrute/stdlib_version
go build -o vncbrute vncbrute.go
sudo cp vncbrute /usr/local/bin/
```

## Usage

```
usage: vncbrute <-c concurrent attempts> <-t timeout> [host] [port] [password_file]

positional arguments:
  host           VNC server host
  port           VNC server port
  password_file  Path to file containing list of passwords

options:
  -h, --help     show this help message and exit
  -c             number of concurrent attempts (default: 1)
  -t             connection timeout (default: 3s)
```

## TO-DO:

- [Divinity Framework](https://github.com/HDN-1D10T/divinity) integration/implementation
