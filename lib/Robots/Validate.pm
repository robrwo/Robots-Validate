package Robots::Validate;

# ABSTRACT: Validate that IP addresses are associated with known robots

use v5.24;

use Moo 1;

use Algorithm::AhoCorasick::XS;
use File::ShareDir qw( dist_file );
use File::Slurper  qw( read_binary );
use List::Util     qw( all any none );
use Net::DNS::Resolver;
use Net::IP qw( ip_expand_address ip_is_ipv4 ip_is_ipv6 ip_splitprefix );
use Net::Patricia;
use Ref::Util qw( is_plain_arrayref is_plain_hashref is_regexpref );
use Sub::Util 1.40 qw( set_subname );
use Syntax::Keyword::Try qw( try );
use TOML::XS;
use Types::Common qw( ArrayRef Bool ConsumerOf HashRef InstanceOf Maybe );

# RECOMMEND PREREQ: CHI 0.40
# RECOMMEND PREREQ: Ref::Util::XS
# RECOMMEND PREREQ: TOML::XS 0.06
# RECOMMEND PREREQ: Type::Tiny::XS

use experimental qw( lexical_subs signatures );

use namespace::autoclean;

our $VERSION = 'v0.3.2';

=begin :prelude

=for stopwords CIDR TOML dotless

=end :prelude

=head1 SYNOPSIS

  use Robots::Validate;

  my $rv = Robots::Validate->new;

  ...

  if ( my $res = $rs->validate( $ip, $user_agent ) ) {
     ...
  }

=head1 DESCRIPTION

This module allows one to validate a robot user-agent string against the IP addresses.

=attr C<resolver>

This is the L<Net::DNS::Resolver> object used for DNS lookups.

This can only be set via the constructor.

=cut

has resolver => (
    is      => 'bare',
    isa     => InstanceOf ['Net::DNS::Resolver'],
    builder => 1,
    handles => {
        _dns_query  => 'query',
        _dns_search => 'search',
    },
);

sub _build_resolver($self) {
    return Net::DNS::Resolver->new;
}

=attr networks

This is a L<Net::Patricia> object used for matching networks.

This can only be set via the constructor.

Note that internally IPv4 addresses are converted to IPv6 addresses.

=cut

has networks => (
    is      => 'bare',
    isa     => InstanceOf ['Net::Patricia'],
    builder => 1,
    handles => {
        _add_string   => 'add_string',
        _match_string => 'match_string',
    },
);

sub _build_networks($self) {
    return Net::Patricia->new(AF_INET6);
}

has _validators => (
    is       => 'ro',
    isa      => HashRef,
    init_arg => undef,
    builder  => sub($self) { return {} },
);

has _agents => (
    is       => 'lazy',
    isa      => InstanceOf ['Algorithm::AhoCorasick::XS'],
    init_arg => undef,
    builder  => \&_build_agents,
);

sub _build_agents($self) {
    # We need to ensure the validators are initialised with the rules
    $self->_init_validators_from_config;
    return Algorithm::AhoCorasick::XS->new( [ keys $self->_validators->%* ] );
}

=attr config

This is an array reference of rule configurations.
Each item is a hash reference with the following keys:

=over

=item name

This is a short string with the rule name.

=item agents

This is an array reference of short strings to match against user agent strings.
It is required.

=item domain

This is a string or array reference of short strings with the domain suffix. e.g. C<.crawl.example.com>,
or with a regular expression C</\.crawl\.example\.com$/>.

It is important that domain suffixes begin with an initial dot.  For
cases where an entire domain name should match, use a regular
expression that anchors the beginning of the string,
e.g. C</^crawl\.example\.com$/>.
Otherwise an imposter domain matching the dotless-suffix would be validated, e.g.
C<imposter-crawl.example.com>.

Also note that the TOML format will require slashes to be escaped, e.g.

    domain = "/\\.google(bot)?\\.com$/"

=item network

This is an optional array reference of CIDR network blocks.

=item match

This specifies the match type.

The possible values are:

=over

=item any

An agent is verified if either the C<domain> or the C<network> match.
This is the default when unspecified.

=item all

An agent is verified is both the C<domain> and the C<network> match.

=back

=back

If the constructor is passed a hash reference, then it is coerced into an array reference of the values, sorted by keys,
where the key is added to the C<name> if it is not already specified.  (The C<agents> and C<network> values will be
coerced into array references.)

If the constructor is passed anything else, it is assumed to be the filename of a TOML file with the configuration.

=cut

has config => (
    is     => 'lazy',
    isa    => ArrayRef [HashRef],
    coerce => sub($ref) {

        return $ref if is_plain_arrayref($ref);

        unless ( is_plain_hashref($ref) ) {
            my $toml = read_binary("$ref");
            $ref = TOML::XS::from_toml($toml)->get();
        }

        if ( is_plain_hashref($ref) ) {

            state sub _normalise( $key, $val ) {
                my %item = $val->%*;
                $item{name}   //= $key;
                for my $key (qw/ agents network /) {
                    $item{$key} = [ $item{$key} ] unless !exists $item{$key} || is_plain_arrayref( $item{$key} );
                }
                return \%item;
            }

            return [ map { _normalise( $_ => $ref->{$_} ) } sort keys $ref->%* ];
        }

        return $ref;
    },
    builder => sub($self) {
        return dist_file( __PACKAGE__ =~ s/::/-/gr, 'robots.toml' );
    }
);

=attr index

This is a hash reference where the keys are rule names and the values are the rules from L</config>.

=cut

has index => (
    is       => 'ro',
    isa      => HashRef,
    init_arg => undef,
    builder  => sub($self) { return {} },
);


=attr locked

This is a boolean to indicate that internal data structures for matching agents have been built, and the rules are locked.

=cut

has locked => (
    is       => 'rwp',
    isa      => Bool,
    init_arg => undef,
);

=head2 cache

This is an optional L<CHI> cache used for matching IP addresses and user agent strings.

See the L</SECURITY CONSIDERATIONS> section for improving the safety of the cache.

=head2 has_cache

This indicates that there is a L</cache>.

=cut

has cache => (
    is        => 'ro',
    isa       => ConsumerOf ['CHI::Driver::Role::Universal'],
    predicate => 1,
);

=head2 cache_options

This is an optional hash reference of L</cache> options to pass to L<CHI/compute>, e.g.

    { expires_in => '8 hours' }

Plain strings are assumed to be C<expires_in> values.

=cut

has cache_options => (
    is     => 'ro',
    isa    => Maybe [HashRef],
    coerce => sub($val) {
        return $val if is_plain_hashref($val);
        return { expires_in => "$val" } if defined $val;
        return undef;
    }
);

=method C<validate>

  my $result = $rv->validate( $ip, $agent, \%opts );

Alternatively, you can pass in a L<Plack> environment:

  my $result = $rv->validate($env);

This method attempts to validate that an IP address C<$ip> is associated with a known robot identified by the C<$agent>.

If C<$ip> is in a known list of network blocks, then it succeeds.
Otherwise it attempts to validate that an IP address belongs to a known
robot by first looking up the hostname that corresponds to the IP address,
and then validating that the hostname resolves to that IP address.
It then checks if the hostname is associated with a
known web robot.

If that succeeds, it returns an array reference containing the C<name> and the matching agent string.

The rule can be looked up from the L</index> attribute.

You can specify the following C<%opts>:

=over

=item no_cache

Do not check the L</cache>.

=item agent

Specify the C<$agent>, for backwards-compatibility with versions before v0.3.0.

This is deprecated and will be removed from a future version.

=back

=cut

sub validate( $self, $ip, $agent = undef, $opts = undef ) {

    if ( is_plain_hashref($agent) && !$opts ) {
        ( $agent, $opts ) = ( $opts, $agent );
        $agent //= $opts->{agent}; # DEPRECATED
    }

    if ( is_plain_hashref($ip) && !$agent ) {
        $agent = $ip->{HTTP_USER_AGENT};
        $ip   =  $ip->{REMOTE_ADDR};
    }

    $opts //= { };

    if ( !$opts->{no_cache} && $self->has_cache ) {
        return $self->cache->compute(
            join( $;, $ip, $agent ),
            $self->cache_options,
            sub { return $self->_revalidate( $ip, $agent // "" ) }
        );
    }

    return $self->_revalidate( $ip, $agent // "" );
}

sub _revalidate( $self, $ip, $agent ) {

    if ( $agent ne "" ) {
        if ( my $str = $self->_agents->first_match($agent) ) {
            my $res = $self->_validators->{$str}->($ip);
            return $res && [ $res => $str ];
        }
    }
    else {
        my $res = $self->_match_ip($ip);
        return $res && [ $res => undef ];
    }

    return undef;
}

sub _add_rule( $self, $rule ) {

    die "The rules are locked" if $self->locked;

    my $name = $rule->{name};
    die "A rule name is required" unless defined $name;

    my $domain  = $rule->{domain};
    my $network = $rule->{network};
    my $type    = $rule->{match} // "any";

    my @fns;

    if ($network) {

        $self->_add_network( $_, $name ) for ( $network->@* );

        push @fns, set_subname "_check_ip_${name}", sub($ip) { $self->_check_ip( $name, $ip ) };
    }

    if ($domain) {

        state sub _to_regexp($domain) {
            return $domain if is_regexpref($domain);
            my ($re) = $domain =~ m[ \A / (.+) / \z ]x;
            $re //= quotemeta($domain) . '\z';
            return qr/${re}/an;
        }

        my $fn;

        if ( is_plain_arrayref($domain) ) {
            my @res = map { _to_regexp($_) } $domain->@*;
            $fn = sub($ip) { $self->_check_dns( $name => \@res, $ip ) };
        }
        else {
            my $re = _to_regexp($domain);
            $fn = sub($ip) { $self->_check_dns( $name => $re, $ip ) };
        }

        push @fns, set_subname "_check_dns_${name}", $fn;
    }

    if (@fns) {

        # TODO: add option for partial matching where false returns undef, i.e. "yes or unknown"

        my $fn = set_subname "_verify_${name}", (

            ( @fns == 1 )
            ? sub($ip) { $fns[0]->($ip) and $name }
            : (

                $type eq "any"
                ? sub($ip) {
                    any { $_->($ip) } @fns and $name;
                  }
                : sub($ip) {
                    all { $_->($ip) } @fns and $name;
                }
            )
        );

        my $validators = $self->_validators;

        if ( my $agents = $rule->{agents} ) {
            for my $str ( $agents->@* ) {
                die "string ${str} already exists in the rules" if exists $validators->{$str};
                $validators->{$str} = $fn;
            }
        }
        else {
            # TODO add support for matching on IP
            die "an agent substring is required";
        }

        $self->index->{$name} = $rule;

    }
    else {

        die "no rules found for ${name}";

    }

}

sub _add_network( $self, $cidr, $name ) {
    my ( $prefix, $len ) = ip_splitprefix($cidr);
    $prefix //= $cidr;

    if ( ip_is_ipv4($prefix) ) {
        $len //= 32;
        $cidr = _normalise_ip($prefix) . '/' . ( $len + 96 );
    }

    try {
        $self->_add_string( $cidr, $name );
    }
    catch ($e) {
        die "add_string failed for '$cidr' with '$name': $e";
    };
}

sub _match_ip( $self, $ip ) {
    return $self->_match_string( _normalise_ip($ip) );
}

sub _check_ip( $self, $name, $ip ) {
    my $check = $self->_match_ip($ip);
    return $name if $check && $check eq $name;
    return undef;
}

# The canonical form used to compare addresses: everything is mapped into the
# ::ffff: IPv6 space already used for Net::Patricia (see _match_ip), then fully
# expanded.  Net::DNS renders an AAAA address as "2001:db8:0:0:0:0:0:7", which
# never string-equals the "2001:db8::7" a web server puts in REMOTE_ADDR, so
# comparing the two textually is not meaningful without this.
sub _normalise_ip($ip) {
    return undef unless defined $ip && length $ip;
    $ip = "::ffff:" . ip_expand_address( $ip, 4 ) if ip_is_ipv4($ip);
    return undef unless ip_is_ipv6($ip);      # ip_expand_address does not validate
    return ip_expand_address( $ip, 6 );
}

# Build the reverse-lookup name here rather than passing an address literal to
# the resolver and relying on it to special-case one.  Net::DNS::Question does
# convert a literal, but Net::DNS::Resolver::Mock -- the resolver the tests use
# -- only does so for IPv4, so relying on that behaviour makes the IPv6 path
# untestable.  Being explicit also stops a hostname that merely looks like an
# address from being silently reinterpreted.
sub _arpa($norm) {
    ( my $nibbles = $norm ) =~ s/://g;
    if ( $nibbles =~ /\A0{20}ffff([[:xdigit:]]{8})\z/a ) {    # IPv4-mapped
        return join( ".", reverse map { hex } $1 =~ /(..)/g ) . ".in-addr.arpa";
    }
    return join( ".", reverse split //, $nibbles ) . ".ip6.arpa";
}

sub _check_dns( $self, $name, $domain, $ip ) {

    my $wanted = _normalise_ip($ip) // return undef;

    my $reply = $self->_dns_query( _arpa($wanted), "PTR" ) or return undef;

    my @hostnames = grep { !!$_ }
      map { $_->can("ptrdname") && $_->ptrdname } $reply->answer;


    if ( is_plain_arrayref($domain) ) {
        my @domains = $domain->@*;
        if ( @domains == 1 ) {
            $domain = $domains[0];
        }
        else {
            my $re = "(" . join( "|",  @domains ) . ")";
            $domain = qr/$re/n;
        }
    }

    my @matched = grep { $_ =~ $domain } @hostnames;

    return undef unless @matched;

    # Only a record of the client's own family can confirm it, so ask for one
    # type rather than both: an IPv4 client normalises into ::ffff:/96.
    my $type = $wanted =~ /\A0000:0000:0000:0000:0000:ffff:/ ? "A" : "AAAA";

    for my $hostname (@matched) {

        my $forward = $self->_dns_query( $hostname, $type ) or next;

        return $name
          if any { ( _normalise_ip($_) // "" ) eq $wanted }
          map    { $_->address }
          grep   { $_->can("address") } $forward->answer;
    }

    return undef;
}

sub _init_validators_from_config($self) {
    for my $rule ( $self->config->@* ) {
        $self->_add_rule( { $rule->%* } );
    }
    $self->_set_locked(1);
}

=head1 KNOWN ISSUES

Many of these rules are not documented, but have been guessed from web traffic.

The networks used by some robots do not consistently support reverse DNS lookups, and may randomly fail.

=head1 SECURITY CONSIDERATIONS

When using the L</cache>, ensure that it is configured to expire the
data by setting L<CHI/expires_in> and digest the keys by setting
L<CHI/max_key_length> to 0.  This is to keep the cache from growing
too large, and to reduce the likelihood of cache backend
vulnerabilities being exploited through user-agent strings.

When specifying a C<domain> for verification rules, ensure that there
is an initial dot in the suffix, or that the regular expression
matches the entire domain name.  Otherwise imposter domains with the
same suffix will be validated.

When the C<network> list contains cloud addresses, it is important to
regularly update the addresses from the documented information, as an
imposter can use abandoned cloud IP addresses.

=head1 prepend:SUPPORT

Only the latest version of this module will be supported.

This module requires Perl v5.24 or later, based on the minimum Perl supported by L<Dist::Zilla>.

=head2 Reporting Bugs and Submitting Feature Requests

=head1 append:SUPPORT

If the bug you are reporting has security implications which make it inappropriate to send to a public issue tracker,
then see F<SECURITY.md> for instructions how to report security vulnerabilities.

=head1 append:AUTHOR

Some of the development of this module was sponsored by Science Photo Library L<https://www.sciencephoto.com>.

=head1 SEE ALSO

The file F<robots.toml> included with this distribution contains links to documented rules.

The TOML specification can be found at L<https://toml.io>.

=cut

1;
