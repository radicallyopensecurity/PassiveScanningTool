PassiveNLSurvey
=============

Welcome to the passive survey tool source code!

From this repository you can build the passive survey tool for Windows, Linux and other platforms compatible with mono. Modify it in any way you can imagine, and share your changes with others!

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

1. TODO

### Linux

1. [Set up Git](https://help.github.com/articles/set-up-git/) and [fork our repository](https://help.github.com/articles/fork-a-repo/).
   If you'd prefer not to use Git, use the 'Download ZIP' button on the right to get the source as a zip file.

1. Installing the complete mono package will allow you to build the project. For apt based operating systems this can be done using **apt-get install mono-complete**.

1. Open your source folder and run **make**.

### Additional target platforms

TODO

Usage
-----

TODO
