#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 3;
use Net::SSLeay;

ok( defined &Net::SSLeay::OP_NO_TLSv1(), 'some random constant exists' );

SKIP: {
    eval "use Test::Exception;";
    skip 'Some tests need Test::Exception', 2 if $@;

    dies_ok( sub { &Net::SSLeay::TXT_RC2_128_CBC_EXPORT40_WITH_MD5() }, 'disabled constant doesn\'t exist' );
    dies_ok( sub { &Net::SSLeay::123x() }, 'invalid constant doesn\'t exist' );
}
