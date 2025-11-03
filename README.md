# Using this template

Please follow the tasks of this task list in order to transform this template repository into your own project repository.

- `.gitlab-ci.yml`
  - [ ] Define a variable `TEST_WITH_GMPY2_DEPENDENCIES` with value `"true"` in case your package defines an optional extra `gmpy` (which installs `gmpy2`).
  - [ ] (optional) You can fix the cicd configuration to a specific reference by adjusting the include:
  ```yaml
  include:
    - project: "pet/lab/cicd/templates"
      file: "python/mpc-template-microlib.yaml"
      ref: "v2.2.3" # <-- fix your preferred tag / ref
  ```
- `LICENSE`
  - [ ] Verify that the copyright year (nearly at the bottom of the license) is the current year.
- `pyproject.toml`
  - [ ] Add relevant keywords to the `keywords` table. (One keyword per line)
  - [ ] If needed, add relevant classifiers to the `classifiers` table, or remove e.g. `Topic :: Security :: Cryptography` if that doesn't fit. For a list of valid classifiers see [here](https://pypi.org/classifiers/). (One classifier per line)
  - [ ] Update the `dependencies` table with all compulsory dependencies. (One dependency per line)
  - [ ] Add any optional package data under the section `[tool.setuptools.package-data]`, e.g. data files, scripts, etcetera. (One line per package data)
  - [ ] Update the `[tool.optional-dependencies]` section.
    - [ ] Update the `tests` variable with the dependencies that are only required for running the tests. (One line per dependency)
    - [ ] (optional) Define new optional install extras and their corresponding dependencies in this section.
- [ ] (optional) `stubs` folder
  - In case you need to store extra stub files for the typing of dependencies those can be placed in a `stubs` folder. This folder is to be placed at the root of the project.
- `README.md`
  - [ ] Remove this tasklist and the containing first section from this README.
  - [ ] Update the `Usage` section to explain how this package should be used and add at least one example to show the most relevant methods and classes of this library.
  - [ ] (optional) Add more (sub)-sections and explanations as you deem necessary.

# TNO PET Lab - Secure Multi-Party Computation (MPC) - Demo - Futurepet

**PROVIDE A ONE PARAGRAPH SUMMARY OF THIS REPOSITORY**

### PET Lab

The TNO PET Lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of PET solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed PET functionalities to boost the development of new protocols and solutions.

The package `tno.mpc.demo.futurepet` is part of the [TNO Python Toolbox](https://github.com/TNO-PET).

_Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws._
_This implementation of cryptographic software has not been audited. Use at your own risk._

## Documentation

Documentation of the `tno.mpc.demo.futurepet` package can be found
[here](https://docs.pet.tno.nl/mpc/demo/futurepet/0.1.0).

## Install

Easily install the `tno.mpc.demo.futurepet` package using `pip`:

```console
$ python -m pip install tno.mpc.demo.futurepet
```

_Note:_ If you are cloning the repository and wish to edit the source code, be
sure to install the package in editable mode:

```console
$ python -m pip install -e 'tno.mpc.demo.futurepet'
```

If you wish to run the tests you can use:

```console
$ python -m pip install 'tno.mpc.demo.futurepet[tests]'
```

## Usage

Show an example of how to use the package, or create and refer to an `scripts/example.py` script.
