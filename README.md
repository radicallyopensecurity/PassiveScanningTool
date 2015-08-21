PassiveNLSurvey
=============

Welcome to the passive survey tool source code!

From this repository you can build the passive survey tool for Windows, Linux and other platforms compatible with mono. Modify it in any way you can imagine, and share your changes with others!

The passive survey tool uses zmap and zgrab results found at the **[scans.io](https://scans.io/)** repository. These results are then compared to a list of hosts. The format is shown in this  **[example](http://www.nirsoft.net/countryip/nl.csv)**. All services found will be written to the output file in addition to all information that is available about this service.

Branches
--------

We publish source for the engine in a single rolling branch.

The **[master branch](https://github.com/radicallyopensecurity/PassiveNLSurvey/tree/master)** tracks [live changes](https://github.com/radicallyopensecurity/PassiveNLSurvey/commits/master) by the team.
This is the cutting edge and may be buggy - it may not even compile. Battle-hardened developers eager to work lock-step with us on the latest and greatest should head here.

Getting up and running
----------------------

The steps below will take you through cloning your own private fork, then compiling and running the tool yourself:

### Windows

1. Install **[GitHub for Windows](https://windows.github.com/)** then **[fork and clone our repository](https://guides.github.com/activities/forking/)**.
   To use Git from the command line, see the [Setting up Git](https://help.github.com/articles/set-up-git/) and [Fork a Repo](https://help.github.com/articles/fork-a-repo/) articles.

   If you'd prefer not to use Git, you can get the source with the 'Download ZIP' button on the right. The built-in Windows zip utility will mark the contents of zip files
   downloaded from the Internet as unsafe to execute, so right-click the zip file and select 'Properties...' and 'Unblock' before decompressing it. Third-party zip utilities don't normally do this.

1. Install **Visual Studio 2013**.
   All desktop editions of Visual Studio 2013 can build the tool, including [Visual Studio Community 2013](http://www.visualstudio.com/products/visual-studio-community-vs), which is available for free.

1. Load the project into Visual Studio by double-clicking on the **PassiveScanning.sln** file. Right click on the **PassiveScanning** target and select **Build**.

### Mac

1. [Set up Git](https://help.github.com/articles/set-up-git/) and [fork our repository](https://help.github.com/articles/fork-a-repo/).
   If you'd prefer not to use Git, use the 'Download ZIP' button on the right to get the source as a zip file.

1. In order to be able to compile, [set up Mono](http://www.mono-project.com/download/).

1. Open your source folder and run **make**.

### Linux

1. [Set up Git](https://help.github.com/articles/set-up-git/) and [fork our repository](https://help.github.com/articles/fork-a-repo/).
   If you'd prefer not to use Git, use the 'Download ZIP' button on the right to get the source as a zip file.

1. Installing the complete mono package will allow you to build the project. For apt based operating systems this can be done using **apt-get install mono-complete**.

1. Open your source folder and run **make**.

Usage
-----

In order to run the program it will need pairs of zmap and zgrab inputs found at the **[scans.io](https://scans.io/)** repository. One of these pairs can for example be **Full IPv4 HTTPS Handshakes**,  [zgrab-results](https://scans.io/zsearch/kxm2gtaf574t4aw1-443-https-tls-full_ipv4-20150817T000100-zgrab-results.json.lz4) and [zmap-results](https://scans.io/zsearch/kxm2gtaf574t4aw1-443-https-tls-full_ipv4-20150817T000100-zmap-results.csv.lz4). Additionally the program will require a list of IP ranges that you are interested in as shown in this **[example](http://www.nirsoft.net/countryip/nl.csv)**. TODO add full example.

You are now ready to run the program, once the program is done running it will output a CSV format file (ip;service;json-data) in addition to the analysis.
