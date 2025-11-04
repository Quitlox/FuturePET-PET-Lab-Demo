# TNO PET Lab - Secure Multi-Party Computation (MPC) - Demo - Futurepet

This repository contains demonstration code for the TNO PET Lab, showcasing secure multi-party computation (MPC) protocols. It demonstrates three core MPC capabilities: secure communication between parties, homomorphic encryption using the Paillier cryptosystem, and secret sharing using Shamir's scheme.

### PET Lab

The TNO PET Lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of PET solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed PET functionalities to boost the development of new protocols and solutions.

The package `tno.mpc.demo.futurepet` is part of the [TNO Python Toolbox](https://github.com/TNO-PET).

_Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws._
_This implementation of cryptographic software has not been audited. Use at your own risk._

## Documentation

Documentation of the `tno.mpc.demo.futurepet` package can be found
[here](https://docs.pet.tno.nl/mpc/demo/futurepet/0.1.0).

## Installation

### Setting up a virtual environment

First, create a Python virtual environment using one of the following methods:

Using the standard Python venv module:
```console
$ python -m venv .venv
```

Or using uv:
```console
$ uv venv
```

### Activating the environment

Activate the virtual environment:

On Linux/macOS:
```console
$ source .venv/bin/activate
```

On Windows:
```console
$ .venv\Scripts\activate
```

### Installing the package

Install the package in editable mode with test dependencies:

```console
$ uv pip install -e ".[tests]"
```

Alternatively, if you're not using uv, you can use regular pip:
```console
$ pip install -e ".[tests]"
```

## Running the Demo

The demo can be run directly using Python:

```console
$ python src/tno/mpc/demo/futurepet/demo.py
```

### Available Demos

The demo file contains three different demonstrations that can be run by uncommenting the corresponding line in the `__main__` block:

1. **Communication Demo** (`demo_communication()`): Demonstrates basic secure message passing between two parties (Alice and Bob).

2. **Homomorphic Encryption Demo** (`demo_homomorphic_encryption()`): Shows how parties can perform computations on encrypted data using the Paillier cryptosystem. Alice encrypts her value, Bob performs addition with his encrypted value, and Alice decrypts the result.

3. **Secret Sharing Demo** (`demo_secret_sharing()`): Demonstrates Shamir's secret sharing scheme with three parties (Alice, Bob, and Charlie), where each party shares a secret value and they collectively compute the sum without revealing individual values.

By default, the secret sharing demo is enabled. To run a different demo, edit the `demo.py` file and uncomment the desired demo function.
