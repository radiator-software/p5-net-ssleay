#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
eval "use Test::Pod::Coverage 1.00";
plan skip_all => "currently disabled";
plan skip_all => "Test::Pod::Coverage 1.00 required for testing POD coverage" if $@;

plan tests => 2;

pod_coverage_ok('Net::SSLeay');
pod_coverage_ok('Net::SSLeay::Handle');
