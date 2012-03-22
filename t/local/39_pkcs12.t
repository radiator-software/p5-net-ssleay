#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 19;
use Net::SSLeay;
use File::Spec;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my $filename1 = File::Spec->catfile('t', 'data', 'pkcs12-no-chain.p12');
my $filename2 = File::Spec->catfile('t', 'data', 'pkcs12-full.p12');
my $filename3 = File::Spec->catfile('t', 'data', 'pkcs12-no-passwd.p12');

{
  my($privkey, $cert, @cachain) = Net::SSLeay::P_PKCS12_load_file($filename1, 1, "secret");
  ok($privkey, '$privkey [1]');
  ok($cert, '$cert [1]');
  is(scalar(@cachain), 0, 'size of @cachain [1]');
  my $subj_name = Net::SSLeay::X509_get_subject_name($cert);
  is(Net::SSLeay::X509_NAME_oneline($subj_name), '/C=US/O=Org/OU=Unit/CN=pkcs12-test', "X509_NAME_oneline [1]");
}

{
  my($privkey, $cert, @cachain) = Net::SSLeay::P_PKCS12_load_file($filename2, 1, "secret");
  ok($privkey, '$privkey [2]');
  ok($cert, '$cert [2]');
  is(scalar(@cachain), 2, 'size of @cachain [2]');
  my $subj_name = Net::SSLeay::X509_get_subject_name($cert);
  my $ca1_subj_name = Net::SSLeay::X509_get_subject_name($cachain[0]);
  my $ca2_subj_name = Net::SSLeay::X509_get_subject_name($cachain[1]);
  is(Net::SSLeay::X509_NAME_oneline($subj_name), '/C=US/O=Org/OU=Unit/CN=pkcs12-test', "X509_NAME_oneline [2/1]");
  like(Net::SSLeay::X509_NAME_oneline($ca1_subj_name), qr/C=.*CN=.*/, "X509_NAME_oneline [2/2]");
  like(Net::SSLeay::X509_NAME_oneline($ca2_subj_name), qr/C=.*CN=.*/, "X509_NAME_oneline [2/3]");
  SKIP: {
    skip("cert order in CA chain is different in openssl pre-1.0.0", 2) unless Net::SSLeay::SSLeay >= 0x01000000;
    is(Net::SSLeay::X509_NAME_oneline($ca1_subj_name), '/C=US/O=Demo1/CN=CA1', "X509_NAME_oneline [2/4]");
    is(Net::SSLeay::X509_NAME_oneline($ca2_subj_name), '/C=US/OU=Demo2/CN=CA2', "X509_NAME_oneline [2/5]");
  }
}

{
  my($privkey, $cert, @cachain) = Net::SSLeay::P_PKCS12_load_file($filename3, 1);
  ok($privkey, '$privkey [3]');
  ok($cert, '$cert [3]');
  is(scalar(@cachain), 0, 'size of @cachain [3]');
  my $subj_name = Net::SSLeay::X509_get_subject_name($cert);
  is(Net::SSLeay::X509_NAME_oneline($subj_name), '/C=US/O=Org/OU=Unit/CN=pkcs12-test', "X509_NAME_oneline [3]");
}

{
  my($privkey, $cert, @should_be_empty) = Net::SSLeay::P_PKCS12_load_file($filename2, 0, "secret");
  ok($privkey, '$privkey [4]');
  ok($cert, '$cert [4]');
  is(scalar(@should_be_empty), 0, 'size of @should_be_empty');
}