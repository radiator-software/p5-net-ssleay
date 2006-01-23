#!/usr/bin/perl
# Test complete connection a number of external SSL web servers

use strict;
use Test::More;
use Net::SSLeay;

my @sites = ('www.cdw.com',
	     'banking.wellsfargo.com',
	     'secure.worldgaming.net',
	     'www.ubs.com',
#            'www.engelschall.com',
#            'www.openssl.org',
#            'app.iplanet.com',
	     );

plan tests => @sites * 2;

my $site;
for $site (@sites) 
{
  SKIP: {
      my ($p, $r, %h) =  Net::SSLeay::get_https($site, 443, '/');
      skip 'could not connect', 2 unless defined $h{SERVER};
      pass('connection');
      ok($r =~ /^HTTP\/1/s, 'correct response');
  }
}
