# NAPALM driver for fortios

This is a [NAPALM](https://napalm.readthedocs.io/en/latest/) driver for fortios (fortigate) using rest API to be able, for now, retrieving some information like:

- interfaces
- interface ip
- firewall policies

## Install

There is no PyPi repo has Orange didn't set up anything for now, to install use command line:

```shell
pip install git+https://github.com/orange-cloudfoundry/napalm-fortios.git@<release version>
```

## Usage

you can use this new driver, example with napalm command line:

```
napalm --user myuser --vendor fortios fg01.qfabric.rproxynet.m2.p.fti.net --optional_args "vdom=root" call get_firewall_policies
```

