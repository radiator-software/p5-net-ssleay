#!/usr/bin/perl

use strict;
use warnings;
use lib 'ext';
use lib '.';
use inc::Module::Install;
use Config;
use File::Spec;

name('Net-SSLeay');
license('perl');
all_from('lib/Net/SSLeay.pm');

ssleay();

requires('MIME::Base64');
requires('Test::More' => '0.60_01');

clean_files(map { fixpath($_) } qw(
    makecert.out
    makecert.err
    sslecho.log
    tcpecho.log
    t/local/ptr_cast_test
    examples/cert.pem
    examples/key.pem
    examples/key.pem.e
    examples/*.0
));

no_index( directory => qw( inc ext helper_script examples ) );
resources( repository => 'http://svn.debian.org/wsvn/net-ssleay' );
resources( bugtracker => 'https://rt.cpan.org/Public/Dist/Display.html?Name=net-ssleay' );

my $regen_script = File::Spec->catfile('helper_script', 'regen_openssl_constants.pl');
my $constants_t = File::Spec->catfile('t', 'local', '21_constants.t');

postamble <<"MAKE";
constants.c : $regen_script
	\$(ABSPERLRUN) $regen_script -gen-c constants.c

$constants_t : $regen_script
	\$(ABSPERLRUN) $regen_script -gen-t $constants_t

SSLeay$Config{'obj_ext'} : constants.c $constants_t

MAKE

WriteAll();
