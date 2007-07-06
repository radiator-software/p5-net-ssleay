#!/usr/bin/perl
# Test complete connection a number of external SSL web servers

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

my @sites = qw(
        www.cdw.com
        banking.wellsfargo.com
        perldition.org
        alioth.debian.org
);

plan tests => @sites * 2;

my $site;
for $site (@sites) {
    SKIP: {
        my ($p, $r, %h) =  Net::SSLeay::get_https($site, 443, '/');
        skip 'could not connect', 2 unless defined $h{'CONTENT-TYPE'};
        pass('connection');
        ok($r =~ /^HTTP\/1/s, 'correct response');
    }
}
