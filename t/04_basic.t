#!/usr/bin/perl

use strict;
use Test::More tests => 4;

use Net::SSLeay;
eval "use Test::Exception;";

SKIP: {
    skip 'Neet Test::Exception for the some tests', 3 if $@;
    lives_ok( sub { Net::SSLeay::randomize() }, 'randomizing' );
    lives_ok( sub { Net::SSLeay::load_error_strings() }, 'loading error strings' );
    lives_ok( sub { Net::SSLeay::SSLeay_add_ssl_algorithms() }, 'adding ssl algorithms' );
}

is(Net::SSLeay::hello(), 1, 'hello world');
