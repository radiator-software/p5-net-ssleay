#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;
use Test::More tests => 6;
use Symbol qw(gensym);
use IPC::Open3;
use Config;

my $input  = File::Spec->catfile(qw( t local ptr_cast_test.c ));
my $output = File::Spec->catfile(qw( t local ptr_cast_test   ));

diag( "cc: $Config{'cc'}" );

unlink $output;

my $out = gensym();
my $err = gensym();

my $pid = open3(undef, $out, $err, $Config{cc}, '-o', $output, $input);
waitpid $pid, 0;

is( $?, 0, 'compiling ptr_cast_test.c' );

is( do { local $/ = undef; <$out> }, '', 'STDOUT empty after compiling' );
is( do { local $/ = undef; <$err> }, '', 'STDERR empty after compoling' );

$pid = open3(undef, $out, $err, "./$output");
waitpid $pid, 0;

is( $?, 0, './ptr_cast_test exited with 0' );

like( do { local $/ = undef; <$out> }, qr/ptr_cast_test:\s+ok\s+/, 'casting pointer integer and back worked' );
ok( !do { local $/ = undef; <$err> }, 'STDERR empty after running' );
