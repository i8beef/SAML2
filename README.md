# SAML2

[![Build status](https://ci.appveyor.com/api/projects/status/prw1j26kc1kvbl4c/branch/release?svg=true)](https://ci.appveyor.com/project/i8beef/saml2/branch/release)
[![Build status](https://ci.appveyor.com/api/projects/status/prw1j26kc1kvbl4c/branch/master?svg=true)](https://ci.appveyor.com/project/i8beef/saml2/branch/master)

SAML2 is a .NET implementation of the OASIS SAML 2.0 specification. It is a fork of the OIOSAML.NET project by the Danish government.

### Where to get it

Run the following command in the NuGet Package Manager console to install the library:

    PM> Install-Package SAML2

### Usage & Examples

See wiki.

### Credits

As this library is a fork of [OIOSAML.NET](https://digitaliser.dk/group/42063/resources), much of the credit goes to them.

Changes from OIOSAML.NET include:
* NuGet package availability.
* More general namespacing.
* Addition of NameIDFormat support.
* Addition of RequestedAuthnContext support.
* Abstraction of logging to providers to eliminate hard dependency on Log4Net.
* Elimination of Trace usage in favor of abstracted logging providers.
* Expanded logging capabilities
* Abstraction of assertion validation into profiles that allow for custom extensions to the SAML spec requirements without needing include arbitrary implementations in the main library (e.g. Danish Government profile, eGov profile, etc.).
* Completely revamped configuration sections
* Ability to auto-download identity provider metadata files at application start time with the [Metadata Fetcher Module](Metadata Fetcher Module)

### License

This library is released under the [Mozilla Public License 2.0 (MPL-2.0)](https://github.com/i8beef/SAML2/blob/master/LICENSE).

### Bug reports

Please create a new issue on the GitHub project homepage.