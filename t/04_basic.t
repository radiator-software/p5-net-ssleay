#!/usr/bin/perl

use strict;
use Test::More tests => 4;
use Test::Exception;

use Net::SSLeay;

lives_ok { Net::SSLeay::randomize() } 'randomizing';
lives_ok { Net::SSLeay::load_error_strings() } 'loading error strings';
lives_ok { Net::SSLeay::SSLeay_add_ssl_algorithms() } 'adding ssl algorithms';

is(Net::SSLeay::hello(), 1, 'hello world');
