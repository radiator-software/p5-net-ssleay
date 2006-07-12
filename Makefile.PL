#!/usr/bin/perl

use strict;
use warnings;
use lib 'ext';
use inc::Module::Install;

name('Net-SSLeay');
all_from('lib/Net/SSLeay.pm');

ssleay();

build_requires('Test::More' => 0.42);

features(
    'POD Testing' => [
        -default => 0,
        recommends('Test::Pod'),
        recommends('Test::Pod::Coverage'),
    ],
    'Exception Testing' => [
        -default => 0,
        recommends('Test::Exception'),
    ],
    'Proxy authentication' => [
        -default => 1,
        recommends('MIME::Base64'),
    ],
);

tests('t/*.t t/*/*.t');
clean_files(map { fixpath($_) } qw(
    makecert.out
    makecert.err
    openssl_path
    sslecho.log
    tcpecho.log
    ptrcasttst
    examples/cert.pem
    examples/key.pem
    examples/key.pem.e
    examples/*.0
));

no_index(qw( inc ext ));

auto_include;
auto_install;
WriteAll;
