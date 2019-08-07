# openssl-ca

## Description

This project contain wrapper-classes for most of the x509 parts in the OpenSSL
API. The wrappers makes error-handling and memory-managment easier compared to
use the plain C-style D API.

**Note:** This project is dependent on dub package openssl which is not fully
uplifted to openssl version 1.1.0h. A pull request exists which at the moment
still waits to be merged into master. Hence you need to manually clone the
origin of the pull request @ `https://github.com/1nfiniteloop/openssl.git` and
checkout branch `x509-uplift-squashed`. Add this package as a local override
with: `dub add-override`.

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

## Future work

* Implement certificate revocation.
