#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 6;
use Net::SSLeay;

eval "use Test::Exception;";

SKIP: {
    skip 'Need Test::Exception for the some tests', 3 if $@;
    lives_ok( sub { Net::SSLeay::randomize() }, 'randomizing' );
    lives_ok( sub { Net::SSLeay::load_error_strings() }, 'loading error strings' );
    lives_ok( sub { Net::SSLeay::SSLeay_add_ssl_algorithms() }, 'adding ssl algorithms' );
    #version numbers: 0x00903100 ~ 0.9.3, 0x0090600f ~ 0.6.9
    ok( Net::SSLeay::SSLeay() >= 0x00903100, 'SSLeay (version min 0.9.3)' );
    isnt( Net::SSLeay::SSLeay_version(), '', 'SSLeay (version string)' );
}

is(Net::SSLeay::hello(), 1, 'hello world');
