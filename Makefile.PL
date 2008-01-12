#!/usr/bin/perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name('Net-SSLeay');
all_from('lib/Net/SSLeay.pm');

ssleay();

requires('MIME::Base64');

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

no_index( directory => qw( inc ext ) );

WriteAll();
