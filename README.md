Welcome to bulk_extractor.

Note: bulk_extractor version 2.0 is now under development. For information, please see [Release 2.0 roadmap in the release-2.0-dev branch](https://github.com/simsong/bulk_extractor/blob/release-2.0-dev/doc/ROADMAP_2.0.md).

To build bulk_extractor in Linux or Mac OS:

1. Make sure required packages have been installed. **You can do this by going into the etc/ directory and looking for a script that installs the necessary packages for your platform.**

2. Then run these commands:

```
./configure
make
make install
```

For detailed instructions on installing packages and building bulk_extractor, read the wiki page here:
https://github.com/simsong/bulk_extractor/wiki/Installing-bulk_extractor

The Windows version of bulk_extractor must be built on Fedora.

To download the Windows installer and/or other releases of bulk_extractor, visit the downloads page here:
http://digitalcorpora.org/downloads/bulk_extractor

For more information on bulk_extractor, visit: https://forensicswiki.xyz/wiki/index.php?title=Bulk_extractor


Tested Configurations
=====================
This release of bulk_extractor has been tested to compile on the following platforms:

* Amazon Linux as of 2019-11-09
* Fedora 32
* Ubuntu 16.04LTS
* Ubuntu 18.04LTS

To configure your operating system, please run the appropriate scripts in the [etc/](/etc) directory.


RECOMMENDED CITATION
====================
If you are writing a scientific paper and using bulk_extractor, please cite it with:

Garfinkel, Simson, Digital media triage with bulk data analysis and bulk_extractor. Computers and Security 32: 56-72 (2013) 
* [Science Direct](https://www.sciencedirect.com/science/article/pii/S0167404812001472)
* [Bibliometrics](https://plu.mx/plum/a/?doi=10.1016/j.cose.2012.09.011&theme=plum-sciencedirect-theme&hideUsage=true)
* [Author's website](https://simson.net/clips/academic/2013.COSE.bulk_extractor.pdf)
```
@article{10.5555/2748150.2748581,
author = {Garfinkel, Simson L.},
title = {Digital Media Triage with Bulk Data Analysis and Bulk_extractor},
year = {2013},
issue_date = {February 2013},
publisher = {Elsevier Advanced Technology Publications},
address = {GBR},
volume = {32},
number = {C},
issn = {0167-4048},
journal = {Comput. Secur.},
month = feb,
pages = {56–72},
numpages = {17},
keywords = {Digital forensics, Bulk data analysis, bulk_extractor, Stream-based forensics, Windows hibernation files, Parallelized forensic analysis, Optimistic decompression, Forensic path, Margin, EnCase}
}
```

