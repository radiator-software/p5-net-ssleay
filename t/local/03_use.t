#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 1;

BEGIN {
    use_ok('Net::SSLeay');
}

diag("");
diag("Testing Net::SSLeay $Net::SSLeay::VERSION");
diag("");
diag("Perl information:");
diag("  Version:         '" . $]  . "'");
diag("  Executable path: '" . $^X . "'");
diag("");
diag("libssl information:");
diag("  SSLEAY_VERSION:      '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_VERSION())  . "'");
diag("  SSLEAY_CFLAGS:       '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_CFLAGS())   . "'");
diag("  SSLEAY_BUILT_ON:     '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_BUILT_ON()) . "'");
diag("  SSLEAY_PLATFORM:     '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_PLATFORM()) . "'");
diag("  SSLEAY_DIR:          '" . Net::SSLeay::SSLeay_version(Net::SSLeay::SSLEAY_DIR())      . "'");
if (eval "&Net::SSLeay::OPENSSL_ENGINES_DIR") {
	diag("  OPENSSL_ENGINES_DIR: '" . Net::SSLeay::OpenSSL_version(Net::SSLeay::OPENSSL_ENGINES_DIR()) . "'");
}
