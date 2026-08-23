# NAME

Robots::Validate - Validate that IP addresses are associated with known robots

# SYNOPSIS

```perl
use Robots::Validate;

my $rv = Robots::Validate->new;

...

if ( my $res = $rs->validate( $ip, $user_agent ) ) {
   ...
}
```

# DESCRIPTION

This module allows one to validate a robot user-agent string against the IP addresses.

# RECENT CHANGES

Changes for version v0.3.2 (2026-08-23)

- Documentation
    - Removed duplicate CONTRIBUTOR.

See the `Changes` file for more details.

# REQUIREMENTS

This module lists the following modules as runtime dependencies:

- [Algorithm::AhoCorasick::XS](https://metacpan.org/pod/Algorithm%3A%3AAhoCorasick%3A%3AXS)
- [File::ShareDir](https://metacpan.org/pod/File%3A%3AShareDir)
- [File::Slurper](https://metacpan.org/pod/File%3A%3ASlurper)
- [List::Util](https://metacpan.org/pod/List%3A%3AUtil)
- [Moo](https://metacpan.org/pod/Moo) version 1 or later
- [Net::DNS::Resolver](https://metacpan.org/pod/Net%3A%3ADNS%3A%3AResolver)
- [Net::IP](https://metacpan.org/pod/Net%3A%3AIP)
- [Net::Patricia](https://metacpan.org/pod/Net%3A%3APatricia)
- [Ref::Util](https://metacpan.org/pod/Ref%3A%3AUtil)
- [Sub::Util](https://metacpan.org/pod/Sub%3A%3AUtil) version 1.40 or later
- [Syntax::Keyword::Try](https://metacpan.org/pod/Syntax%3A%3AKeyword%3A%3ATry)
- [TOML::XS](https://metacpan.org/pod/TOML%3A%3AXS)
- [Types::Common](https://metacpan.org/pod/Types%3A%3ACommon)
- [experimental](https://metacpan.org/pod/experimental)
- [namespace::autoclean](https://metacpan.org/pod/namespace%3A%3Aautoclean)
- [perl](https://metacpan.org/pod/perl) version v5.24.0 or later

See the `cpanfile` file for the full list of prerequisites.

# INSTALLATION

The latest version of this module (along with any dependencies) can be installed from [CPAN](https://www.cpan.org) with the `cpan` tool that is included with Perl:

```
cpan Robots::Validate
```

You can also extract the distribution archive and install this module (along with any dependencies):

```
cpan .
```

You can also install this module manually using the following commands:

```
perl Makefile.PL
make
make test
make install
```

If you are working with the source repository, then it may not have a `Makefile.PL` file.  But you can use the [Dist::Zilla](https://dzil.org/) tool in anger to build and install this module:

```
dzil build
dzil test
dzil install --install-command="cpan ."
```

For more information, see [How to install CPAN modules](https://www.cpan.org/modules/INSTALL.html).

# SECURITY CONSIDERATIONS

When using the ["cache"](#cache), ensure that it is configured to expire the data and digest the keys by setting
["max\_key\_length" in CHI](https://metacpan.org/pod/CHI#max_key_length) to 0.  This is to keep the cache from growing too large, and to reduce the likelihood of cache
backend vulnerabilities being exploited through user-agent strings.

# SUPPORT

Only the latest version of this module will be supported.

This module requires Perl v5.24 or later, based on the minimum Perl supported by [Dist::Zilla](https://metacpan.org/pod/Dist%3A%3AZilla).

## Reporting Bugs and Submitting Feature Requests

Please report any bugs or feature requests on the bugtracker website
[https://github.com/robrwo/Robots-Validate/issues](https://github.com/robrwo/Robots-Validate/issues)

When submitting a bug or request, please include a test-file or a
patch to an existing test-file that illustrates the bug or desired
feature.

If the bug you are reporting has security implications which make it inappropriate to send to a public issue tracker,
then see `SECURITY.md` for instructions how to report security vulnerabilities.

# SOURCE

The development version is on github at [https://github.com/robrwo/Robots-Validate](https://github.com/robrwo/Robots-Validate)
and may be cloned from [https://github.com/robrwo/Robots-Validate.git](https://github.com/robrwo/Robots-Validate.git)

# AUTHOR

Robert Rothenberg <perl@rhizomnic.com>

Some of the development of this module was sponsored by Science Photo Library [https://www.sciencephoto.com](https://www.sciencephoto.com).

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2018-2026 by Robert Rothenberg.

This is free software, licensed under:

```
The Artistic License 2.0 (GPL Compatible)
```

# SEE ALSO

The file `robots.toml` included with this distribution contains links to documented rules.
