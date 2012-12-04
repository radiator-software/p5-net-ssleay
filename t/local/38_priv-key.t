#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 10;
use Net::SSLeay;
use File::Spec;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::OpenSSL_add_all_algorithms();

my $key_pem_encrypted       = File::Spec->catfile('t', 'data', 'test_CA1.encrypted_key.pem');
my $key_pem                 = File::Spec->catfile('t', 'data', 'test_CA1.key.pem');

{
  ok(my $bio_pem                 = Net::SSLeay::BIO_new_file($key_pem, 'r'), "BIO_new_file 3");
  ok(Net::SSLeay::PEM_read_bio_PrivateKey($bio_pem), "PEM_read_bio_PrivateKey no password");
}

{
  ok(my $bio_pem_encrypted = Net::SSLeay::BIO_new_file($key_pem_encrypted, 'r'), "BIO_new_file");
  ok(Net::SSLeay::PEM_read_bio_PrivateKey($bio_pem_encrypted, sub {"secret"}), "PEM_read_bio_PrivateKey encrypted - callback");
}

{
  ok(my $bio_pem_encrypted = Net::SSLeay::BIO_new_file($key_pem_encrypted, 'r'), "BIO_new_file");
  ok(Net::SSLeay::PEM_read_bio_PrivateKey($bio_pem_encrypted, undef, "secret"), "PEM_read_bio_PrivateKey encrypted - password");
}

{
  ok(my $bio_pem_encrypted = Net::SSLeay::BIO_new_file($key_pem_encrypted, 'r'), "BIO_new_file");
  ok(!Net::SSLeay::PEM_read_bio_PrivateKey($bio_pem_encrypted, sub {"invalid"}), "PEM_read_bio_PrivateKey encrypted - callback (wrong password)");
}

{
  ok(my $bio_pem_encrypted = Net::SSLeay::BIO_new_file($key_pem_encrypted, 'r'), "BIO_new_file");
  ok(!Net::SSLeay::PEM_read_bio_PrivateKey($bio_pem_encrypted, undef, "invalid"), "PEM_read_bio_PrivateKey encrypted - password (wrong password)");
}
