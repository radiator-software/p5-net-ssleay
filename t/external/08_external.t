#!/usr/bin/perl
# Test complete connection a number of external SSL web servers

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

my @sites = qw(
        www.cdw.com
        banking.wellsfargo.com
        www.open.com.au
        alioth.debian.org
);
@sites = split(/:/, $ENV{SSLEAY_SITES}) if exists $ENV{SSLEAY_SITES};
if (@sites) {
    plan tests => scalar @sites * 2;
}
else {
    plan skip_all => 'No external hosts specified for SSL testing';
}

my $site;
for $site (@sites) {
    SKIP: {
        my ($p, $r, %h) =  Net::SSLeay::get_https($site, 443, '/');
        skip 'could not connect', 2 unless defined $h{'CONTENT-TYPE'};
        pass('connection');
        ok($r =~ /^HTTP\/1/s, 'correct response');
    }
}
