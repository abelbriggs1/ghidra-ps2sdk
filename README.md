# Ghidra - PS2SDK

An extension for Ghidra which adds a binary analyzer and type databases for the
official Playstation 2 Software Development Kit (SDK) libraries. The analyzer can
detect, label, and apply C function signatures and structures to
functions in a Playstation 2 Emotion Engine (EE) executable.

## Requirements

`ghidra-ps2sdk` requires [`ghidra-emotionengine-reloaded`](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/)
to be installed in order to work correctly.

## Installing

- Download the latest release of [`ghidra-emotionengine-reloaded`](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases).
- Download the latest release of [`ghidra-ps2sdk`](https://github.com/abelbriggs1/ghidra-ps2sdk/releases).
- Install both `zip` files using the instructions in Ghidra's [documentation](https://ghidra-sre.org/InstallationGuide.html#Extensions).

## Building

If you want to build the extension yourself, install gradle and run:

```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

## Legality

This project contains function declarations and structures for Sony's proprietary
PS2 SDK APIs, and as such, may fall under a legal grey zone of copyright law.

This extension does not and will never reference or incorporate
any Sony implementation source code, and contributions which do so will not be
accepted. However, some information may be sourced from SDK header files which
define the Sony APIs.

The author of this extension makes no claim of copyright on any Sony proprietary
APIs or structures. This extension exists for educational and research purposes only.
