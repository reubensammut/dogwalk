# dogwalk
A pure python implementation of microsoft-diagcab-rce-poc from Imre Rad

After the recent CVE-2022-30190 (a.k.a Follina) came out, a previously 
reported vulnerability on MSDT, the tool used for the Follina exploit, 
resurfaced. This vulnerability was reported to Microsoft in January 2020 
by Imre Rad. Microsoft had deemed this as being not a security issue. 

This repository is a python implementation of Imre Rad's proof of concept
found [here](https://github.com/irsl/microsoft-diagcab-rce-poc). My 
implementation further simplifies the exploit by generating the .diagcab 
file required pointing to an attacker controlled IP and port.  
The explanation of how this exploit works can be found in Imre Rad's 
[write up](https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd).

## Usage

```
usage: dogwalk [-h] [-c CABNAME] [-i INJECT_PATH] lhost lport path

positional arguments:
  lhost                 IP Address which msdt connects to
  lport                 Port which msdt connects to
  path                  Path where malicious files are hosted

optional arguments:
  -h, --help            show this help message and exit
  -c CABNAME, --cabname CABNAME
                        Name of diagcab to host
  -i INJECT_PATH, --inject-path INJECT_PATH
                        Relative path where the downloaded files by msdt will be stored
```
