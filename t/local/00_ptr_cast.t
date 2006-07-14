#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;
use Test::More tests => 2;
use Config;

my $input  = File::Spec->catfile(qw( t local ptr_cast_test.c ));
my $output = File::Spec->catfile(qw( t local ptr_cast_test   ));

diag( "cc: $Config{'cc'}" );

ok( system("$Config{'cc'} -o $output $input") == 0, 'compiling ptr_cast_test.c' );
ok( system("./$output") == 0 );
