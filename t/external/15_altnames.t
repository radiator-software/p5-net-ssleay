#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SSLeay;

my @sites = qw(
        signin.ebay.de
);

@sites = split(/:/, $ENV{SSLEAY_ALTNAME_SITES})
    if exists $ENV{SSLEAY_ALTNAME_SITES};

if (@sites) {
    plan tests => scalar @sites * 3;
}
else {
    plan skip_all => 'No external hosts specified for SSL testing';
}

for my $site (@sites) {
    SKIP: {
        my ($p, $r, $c) =  Net::SSLeay::sslcat($site, 443, 'GET / HTTP/1.0');
        skip 'could not connect', 3 unless defined $c;
        pass('connection');

        my @altnames = Net::SSLeay::X509_get_subjectAltNames($c);
        ok(scalar @altnames, 'get_subjectAltNames works');
        ok(scalar @altnames % 2 == 0, 'get_subjectAltNames returns pairs');
    }
}
