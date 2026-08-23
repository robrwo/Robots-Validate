#!perl

use Test2::V0;

use Test::File::ShareDir -share => {
    -dist => {
        "Robots-Validate" => "share"
    }
};

use CHI;
use List::Util ();
use Net::DNS::Resolver::Mock;

use Robots::Validate;

my $res = Net::DNS::Resolver::Mock->new;
$res->zonefile_parse(
    <<ZONE
crawl-66-249-66-67.googlebot.com  84569 A       66.249.66.67
67.66.249.66.in-addr.arpa. 84569 IN     PTR     crawl-66-249-66-67.googlebot.com.
ZONE
);

my %store;
my $cache = CHI->new(
    driver         => 'Memory',
    datastore      => \%store,
    key_digester   => 'SHA-256',
    max_key_length => 0,
);

ok my $rv = Robots::Validate->new(
    resolver => $res,
    cache    => $cache,
    cache_options => '8 hours',
  ),
  'Robots::Validate';

is $rv->cache_options, { expires_in => '8 hours' }, 'cache_options coercion';

my $has_google = List::Util::any { $_->{name} eq "google" } $rv->config->@*;
ok $has_google, "google in config";

ok $rv->_check_dns( 1, qr/\.googlebot\.com$/, '66.249.66.67' ), '_check_dns';

ok $rv->_agents, 'agents initialized';

is
  $rv->_revalidate(
    '66.249.66.67',
"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.186 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  ),
  [ "google" => "Googlebot" ],
  '_revalidate';

ok !%store, 'empty cache';

is
  $rv->validate(
    '66.249.66.67',
"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.186 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  ),
  [ "google" => "Googlebot" ],
  'validate';

ok !!%store, 'non-empty cache';

is
  $rv->validate(
    '66.249.66.67',
"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7871.186 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  ),
  [ "google" => "Googlebot" ],
  'validate';

done_testing;
