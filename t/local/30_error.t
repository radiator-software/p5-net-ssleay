#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

plan skip_all => 'Currently disabled';

eval "use Test::Exception;";
plan skip_all => "Test::Exception required." if $@;

plan tests => 4;

use Net::SSLeay;

Net::SSLeay::load_error_strings();

dies_ok( sub { Net::SSLeay::die_now() }, 'die_now dies without errors' );
lives_ok( sub { Net::SSLeay::die_if_ssl_error() }, 'die_if_ssl_error lives without errors' );

Net::SSLeay::ERR_put_error(
        44, #lib
         1, #func
        15, #reason
         1, #file
         1, #line
); #FIXME: This is not a valid error message and raises warnings.

dies_ok( sub { Net::SSLeay::die_now() }, 'die_now dies with errors' );

Net::SSLeay::ERR_put_error(
        44, #lib
         1, #func
        15, #reason
         1, #file
         1, #line
); #FIXME: This is not a valid error message and raises warnings.

dies_ok( sub { Net::SSLeay::die_if_ssl_error() }, 'die_if_ssl_error dies with errors' );
