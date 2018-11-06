package Robots::Validate;

# ABSTRACT: validate IP addresses are associated with known robots

use v5.10;

use Moo 1;

use List::Util 1.33 qw/ first none /;
use Net::DNS::Resolver;
use Types::Standard -types;

# RECOMMEND PREREQ: Type::Tiny::XS
# RECOMMEND PREREQ: Ref::Util::XS

use namespace::autoclean;

our $VERSION = 'v0.1.2';

=head1 SYNOPSIS

  use Robots::Validate;

  my $rv = Robots::Validate->new;

  ...

  if ( $rs->validate( $ip, \%opts ) ) { ...  }

=head1 DESCRIPTION


=attrib C<resolver>

This is the L<Net::DNS::Resolver> used for DNS lookups.

=cut

has resolver => (
    is      => 'lazy',
    isa     => InstanceOf ['Net::DNS::Resolver'],
    builder => 1,
);

sub _build_resolver {
    return Net::DNS::Resolver->new;
}

=attrib C<robots>

This is an array reference of rules with information about
robots. Each item is a hash reference with the following keys:

=over

=item C<name>

The name of the robot.

=item C<agent>

A regular expression for matching against user agent names.

=item C<domain>

A regular expression for matching against the hostname.

=back

=cut

has robots => (
    is  => 'lazy',
    isa => ArrayRef [
        Dict [
            name   => Str,
            agent  => Optional [RegexpRef],
            domain => RegexpRef,
        ]
    ],
    builder => 1,
);

sub _build_robots {
    return [

        {
            name   => 'Baidu',
            agent  => qr/\bBaiduspider\b/,
            domain => qr/\.crawl\.baidu\.com$/,

        },

        {
            name   => 'Bing',
            agent  => qr/\b(?:Bingbot|MSNBot|AdIdxBot|BingPreview)\b/i,
            domain => qr/\.search\.msn\.com$/,

        },

        {
            name   => 'Google',
            agent  => qr/\bGoogle(?:bot?)\b/i,
            domain => qr/\.google(?:bot)?\.com$/,
        },

        {
            name   => 'Yahoo',
            agent  => qr/yahoo/i,
            domain => qr/\.crawl\.yahoo\.net$/,

        },

        {
            name   => "Yandex",
            agent  => qr/Yandex/,
            domain => qr/\.yandex\.(?:com|ru|net)$/,
        },

    ];
}

=attrib C<die_on_error>

When true, L</validate> will die on a L</resolver> failure.

By default it is false.

=cut

has die_on_error => (
    is      => 'lazy',
    isa     => Bool,
    default => 0,
);

=method C<validate>

  my $result = $rv->validate( $ip, \%opts );

This method attempts to validate that an IP address belongs to a known
robot by first looking up the hostname that corresponds to the IP address,
and then validating that the hostname resolves to that IP address.

If this succeeds, it then checks if the hostname is associated with a
known web robot.

If that succeeds, it returns a copy of the matched rule from L</robots>.

You can specify the following C<%opts>:

=over

=item C<agent>

This is the user-agent string. If it does not match, then the DNS lookkups
will not be performed.

It is optional.

=back

=cut

sub validate {
    my ( $self, $ip, $args ) = @_;

    my $res = $self->resolver;

    # Reverse DNS

    my $hostname;

    if ( my $reply = $res->query($ip) ) {
        ($hostname) = map { $_->ptrdname } $reply->answer;
    }
    else {
        die $res->errorstring if $self->die_on_error;
    }

    return unless $hostname;

    $args //= {};
    $args->{forward} //= 1;

    my $agent = $args->{agent};

    my @matches =
      grep { !$agent || $agent =~ $_->{agent} } @{ $self->robots };

    my $reply = $res->search( $hostname, "A" )
        or $self->die_on_error && die $res->errorstring;

    return unless $reply;

    if (
        none { $_ eq $ip } (
            map  { $_->address }
            grep { $_->can('address') } $reply->answer
        )
        )
    {
        return;
    }


    if ( my $match = first { $hostname =~ $_->{domain} } @matches ) {

        return {
            %$match,
            hostname   => $hostname,
            ip_address => $ip,
        };

    }

    return;
}

=head1 SEE ALSO

=over

=item L<Verifying Bingbot|https://www.bing.com/webmaster/help/how-to-verify-bingbot-3905dc26>

=item L<Verifying Googlebot|https://support.google.com/webmasters/answer/80553>

=item L<How to check that a robot belongs to Yandex|https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html>

=back

=cut

1;
