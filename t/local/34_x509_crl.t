#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 41;
use Net::SSLeay;
use File::Spec;

#use File::Slurp;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

my $ca_crt_pem = File::Spec->catfile('t', 'data', 'test_CA1.crt.pem');
my $ca_key_pem = File::Spec->catfile('t', 'data', 'test_CA1.key.pem');
ok(my $bio1 = Net::SSLeay::BIO_new_file($ca_crt_pem, 'r'), "BIO_new_file 1");
ok(my $ca_cert = Net::SSLeay::PEM_read_bio_X509($bio1), "PEM_read_bio_X509");
ok(my $bio2 = Net::SSLeay::BIO_new_file($ca_key_pem, 'r'), "BIO_new_file 2");
ok(my $ca_pk = Net::SSLeay::PEM_read_bio_PrivateKey($bio2), "PEM_read_bio_PrivateKey");

{ ### X509_CRL show info
  my $crl_der = File::Spec->catfile('t', 'data', 'verisign.crl.der');
  my $crl_pem = File::Spec->catfile('t', 'data', 'verisign.crl.pem');

  ok(my $bio1 = Net::SSLeay::BIO_new_file($crl_der, 'rb'), "BIO_new_file 1");
  ok(my $bio2 = Net::SSLeay::BIO_new_file($crl_pem, 'r'), "BIO_new_file 2");

  ok(my $crl1 = Net::SSLeay::d2i_X509_CRL_bio($bio1), "d2i_X509_CRL_bio");
  ok(my $crl2 = Net::SSLeay::PEM_read_bio_X509_CRL($bio2), "PEM_read_bio_X509_CRL");

  ok(my $name1 = Net::SSLeay::X509_CRL_get_issuer($crl1), "X509_CRL_get_issuer 1");
  ok(my $name2 = Net::SSLeay::X509_CRL_get_issuer($crl2), "X509_CRL_get_issuer 2");
  is(Net::SSLeay::X509_NAME_cmp($name1, $name2), 0, "X509_NAME_cmp");

  is(Net::SSLeay::X509_NAME_print_ex($name1), 'CN=VeriSign Class 3 Extended Validation SSL CA,OU=Terms of use at https://www.verisign.com/rpa (c)06,OU=VeriSign Trust Network,O=VeriSign\, Inc.,C=US', "X509_NAME_print_ex");
  
  ok(my $time_last = Net::SSLeay::X509_CRL_get_lastUpdate($crl1), "X509_CRL_get_lastUpdate");
  ok(my $time_next = Net::SSLeay::X509_CRL_get_nextUpdate($crl1), "X509_CRL_get_nextUpdate");
  SKIP: {
    skip 'openssl-0.9.7e required', 2 unless Net::SSLeay::SSLeay >= 0x0090705f; 
    is(Net::SSLeay::P_ASN1_TIME_get_isotime($time_last), "2012-03-08T21:00:13Z", "P_ASN1_TIME_get_isotime last");
    is(Net::SSLeay::P_ASN1_TIME_get_isotime($time_next), "2012-03-15T21:00:13Z", "P_ASN1_TIME_get_isotime next");
  }
  
  is(Net::SSLeay::X509_CRL_get_version($crl1), 0, "X509_CRL_get_version");
  ok(my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1"), "EVP_get_digestbyname");
  is(unpack("H*",Net::SSLeay::X509_CRL_digest($crl1, $sha1_digest)), "2a49fa78444070d2bce08b2ea5213099b3e065fd", "X509_CRL_digest");  
}

{ ### X509_CRL create
  ok(my $crl = Net::SSLeay::X509_CRL_new(), "X509_CRL_new");
  
  ok(my $name = Net::SSLeay::X509_get_subject_name($ca_cert), "X509_get_subject_name");
  SKIP: {
    skip('requires openssl-0.9.7', 1) unless Net::SSLeay::SSLeay >= 0x0090700f;
    ok(Net::SSLeay::X509_CRL_set_issuer_name($crl, $name), "X509_CRL_set_issuer_name");
  }
  
  if (Net::SSLeay::SSLeay >= 0x0090705f) {
    Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_CRL_get_lastUpdate($crl), "2010-02-01T00:00:00Z");
    Net::SSLeay::P_ASN1_TIME_set_isotime(Net::SSLeay::X509_CRL_get_nextUpdate($crl), "2011-02-01T00:00:00Z");
  }
  else {
    # P_ASN1_TIME_set_isotime not available before openssl-0.9.7e
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_CRL_get_lastUpdate($crl), 0);
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_CRL_get_lastUpdate($crl), 0);
  }
  
  SKIP: {
    skip('requires openssl-0.9.7', 2) unless Net::SSLeay::SSLeay >= 0x0090700f;
    ok(Net::SSLeay::X509_CRL_set_version($crl, 1), "X509_CRL_set_version");
    my $ser = Net::SSLeay::ASN1_INTEGER_new();
    Net::SSLeay::P_ASN1_INTEGER_set_hex($ser, "4AFED5654654BCEDED4AFED5654654BCEDED");
    ok(Net::SSLeay::P_X509_CRL_set_serial($crl, $ser), "P_X509_CRL_set_serial");
    Net::SSLeay::ASN1_INTEGER_free($ser);
  }
  
  my @rev_table = (
    { serial_hex=>'1A2B3D', rev_datetime=>"2011-02-01T00:00:00Z", comp_datetime=>"2911-11-11T00:00:00Z", reason=>2 }, # 2 = cACompromise
    { serial_hex=>'2A2B3D', rev_datetime=>"2011-03-01T00:00:00Z", comp_datetime=>"2911-11-11T00:00:00Z", reason=>3 }, # 3 = affiliationChanged
  );
  
  my $rev_datetime = Net::SSLeay::ASN1_TIME_new();
  my $comp_datetime = Net::SSLeay::ASN1_TIME_new();
  for my $item (@rev_table) {  
    if (Net::SSLeay::SSLeay >= 0x0090705f) { 
      Net::SSLeay::P_ASN1_TIME_set_isotime($rev_datetime, $item->{rev_datetime});
      Net::SSLeay::P_ASN1_TIME_set_isotime($comp_datetime, $item->{comp_datetime});
    }
    else {
      # P_ASN1_TIME_set_isotime not available before openssl-0.9.7e
      Net::SSLeay::X509_gmtime_adj($rev_datetime, 0);
      Net::SSLeay::X509_gmtime_adj($comp_datetime, 0);
    }
    SKIP: {
      skip('requires openssl-0.9.7', 1) unless Net::SSLeay::SSLeay >= 0x0090700f;
      ok(Net::SSLeay::P_X509_CRL_add_revoked_serial_hex($crl, $item->{serial_hex}, $rev_datetime, $item->{reason}, $comp_datetime), "P_X509_CRL_add_revoked_serial_hex");        
    }
  }
  Net::SSLeay::ASN1_TIME_free($rev_datetime);
  Net::SSLeay::ASN1_TIME_free($comp_datetime);
  
  ok(my $sha1_digest = Net::SSLeay::EVP_get_digestbyname("sha1"), "EVP_get_digestbyname");
  SKIP: {
    skip('requires openssl-0.9.7', 1) unless Net::SSLeay::SSLeay >= 0x0090700f;
    ok(Net::SSLeay::X509_CRL_sort($crl), "X509_CRL_sort");
  }
  ok(Net::SSLeay::X509_CRL_sign($crl, $ca_pk, $sha1_digest), "X509_CRL_sign");
  
  like(my $crl_pem = Net::SSLeay::PEM_get_string_X509_CRL($crl), qr/-----BEGIN X509 CRL-----/, "PEM_get_string_X509_CRL");
    
  #write_file("tmp.crl.pem", $crl_pem);
  
  is(Net::SSLeay::X509_CRL_free($crl), undef, "X509_CRL_free");
}

{ ### special tests
  my $crl_der = File::Spec->catfile('t', 'data', 'test_CA1.crl.der');
  ok(my $bio = Net::SSLeay::BIO_new_file($crl_der, 'rb'), "BIO_new_file");
  ok(my $crl = Net::SSLeay::d2i_X509_CRL_bio($bio), "d2i_X509_CRL_bio");
  is(Net::SSLeay::X509_CRL_verify($crl, Net::SSLeay::X509_get_pubkey($ca_cert)), 1, "X509_CRL_verify");

  ok(my $time_last = Net::SSLeay::X509_CRL_get_lastUpdate($crl), "X509_CRL_get_lastUpdate");
  ok(my $time_next = Net::SSLeay::X509_CRL_get_nextUpdate($crl), "X509_CRL_get_nextUpdate");
  
  SKIP: {
    skip('requires openssl-0.9.7', 2) unless Net::SSLeay::SSLeay >= 0x0090700f;
    ok(my $sn = Net::SSLeay::P_X509_CRL_get_serial($crl), "P_X509_CRL_get_serial");
    is(Net::SSLeay::ASN1_INTEGER_get($sn), 2, "ASN1_INTEGER_get"); 
  }
  
  SKIP: {
    skip('requires openssl-0.9.7', 3) unless Net::SSLeay::SSLeay >= 0x0090700f;
    ok(my $crl2 = Net::SSLeay::X509_CRL_new(), "X509_CRL_new");
    ok(Net::SSLeay::X509_CRL_set_lastUpdate($crl2, $time_last), "X509_CRL_set_lastUpdate");
    ok(Net::SSLeay::X509_CRL_set_nextUpdate($crl2, $time_next), "X509_CRL_set_nextUpdate");
    Net::SSLeay::X509_CRL_free($crl2);
  }
}
