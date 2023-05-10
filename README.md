# openssl-ca

## Description

This project contain wrapper-classes for most of the x509 parts in the OpenSSL
API. The wrappers makes error-handling and memory-managment easier compared to
use the plain C-style D API.

## Usage

Run unittests with `dub test`.

Examples is available under `examples/` folder. You can run them simply as a
script, example `examples/make_cert.d`.

## Development environment

This project is developed in Visual Studio Code (VS Code) "insiders"
<https://code.visualstudio.com/insiders/>. Currently (at the time of writing)
only this pre-release version supports the plugin "remote development". This
plugin makes it possible to have the development environment inside a
container, see more @ <https://code.visualstudio.com/docs/remote/containers>.

To setup the development environment you only need to open this project in VS
Code and a notification appears where you can choose to open the project inside
a container. All the tools and dependencies will be installed and set-up
accordingly to what's specified in the `.devcontainer/Dockerfile`. No further
dependencies, tools or library installations is needed, the only prerequisite
on the host is that Docker is installed.

## License

MIT

## References

Some sources of inspiration used within this project:

* OpenSSL api: <https://www.openssl.org/docs/manmaster/man3/>
* OpenSSL source: <https://github.com/openssl/openssl>
