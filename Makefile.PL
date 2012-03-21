#!/usr/bin/perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name('Net-SSLeay');
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

postamble <<MAKE;
constants.c :: helper_script/regen_openssl_constants.pl
	\$(ABSPERLRUN) helper_script/regen_openssl_constants.pl -gen-c constants.c

t/local/21_constants.t :: helper_script/regen_openssl_constants.pl
	\$(ABSPERLRUN) helper_script/regen_openssl_constants.pl -gen-t t/local/21_constants.t
MAKE

WriteAll();
