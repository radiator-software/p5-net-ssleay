#!/usr/bin/perl
#
# Test various verify and ASN functions
# added 2010-04-16

use strict;
use warnings;
use Test::More tests => 25;
use Net::SSLeay;

my $pm = Net::SSLeay::X509_VERIFY_PARAM_new();
ok($pm, 'X509_VERIFY_PARAM_new');
my $pm2 = Net::SSLeay::X509_VERIFY_PARAM_new();
ok($pm2, 'X509_VERIFY_PARAM_new 2');
ok(Net::SSLeay::X509_VERIFY_PARAM_inherit($pm2, $pm), 'X509_VERIFY_PARAM_inherit');
ok(Net::SSLeay::X509_VERIFY_PARAM_set1($pm2, $pm), 'X509_VERIFY_PARAM_inherit');
ok(Net::SSLeay::X509_VERIFY_PARAM_set1_name($pm, 'fred'), 'X509_VERIFY_PARAM_set1_name');
ok(Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS() == 0x40, 'X509_V_FLAG_ALLOW_PROXY_CERTS');

ok(Net::SSLeay::X509_VERIFY_PARAM_set_flags($pm, Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS()), 'X509_VERIFY_PARAM_set_flags');
ok(Net::SSLeay::X509_VERIFY_PARAM_get_flags($pm) == Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS(), 'X509_VERIFY_PARAM_get_flags');
ok(Net::SSLeay::X509_VERIFY_PARAM_clear_flags($pm, Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS()), 'X509_VERIFY_PARAM_clear_flags');
ok(Net::SSLeay::X509_VERIFY_PARAM_get_flags($pm) == 0,
'X509_VERIFY_PARAM_get_flags');
ok(Net::SSLeay::X509_PURPOSE_SSL_CLIENT() == 1, 'X509_PURPOSE_SSL_CLIENT');
ok(Net::SSLeay::X509_VERIFY_PARAM_set_purpose($pm, Net::SSLeay::X509_PURPOSE_SSL_CLIENT()), 'X509_VERIFY_PARAM_set_purpose');
ok(Net::SSLeay::X509_TRUST_EMAIL() == 4, 'X509_TRUST_EMAIL');
ok(Net::SSLeay::X509_VERIFY_PARAM_set_trust($pm, Net::SSLeay::X509_TRUST_EMAIL()), 'X509_VERIFY_PARAM_set_trust');
Net::SSLeay::X509_VERIFY_PARAM_set_depth($pm, 5);
Net::SSLeay::X509_VERIFY_PARAM_set_time($pm, time);

# Test ASN1 objects
my $asn_object = Net::SSLeay::OBJ_txt2obj('1.2.3.4', 0);
ok($asn_object, 'OBJ_txt2obj');
ok(Net::SSLeay::OBJ_obj2txt($asn_object, 0) eq '1.2.3.4', 'OBJ_obj2txt');

ok(Net::SSLeay::OBJ_txt2nid('1.2.840.113549.1') == 2, 'OBJ_txt2nid');   # NID_pkcs
ok(Net::SSLeay::OBJ_txt2nid('1.2.840.113549.2.5') == 4, 'OBJ_txt2nid'); # NID_md5

ok(Net::SSLeay::OBJ_ln2nid('RSA Data Security, Inc. PKCS') == 2, 'OBJ_ln2nid'); # NID_pkcs
ok(Net::SSLeay::OBJ_ln2nid('md5') == 4, 'OBJ_ln2nid'); # NID_md5

ok(Net::SSLeay::OBJ_sn2nid('pkcs') == 2, 'OBJ_sn2nid'); # NID_pkcs
ok(Net::SSLeay::OBJ_sn2nid('MD5') == 4, 'OBJ_sn2nid'); # NID_md5

my $asn_object2 = Net::SSLeay::OBJ_txt2obj('1.2.3.4', 0);
ok(Net::SSLeay::OBJ_cmp($asn_object2, $asn_object) == 0, 'OBJ_cmp');
$asn_object2 = Net::SSLeay::OBJ_txt2obj('1.2.3.5', 0);
ok(Net::SSLeay::OBJ_cmp($asn_object2, $asn_object) == 1, 'OBJ_cmp');

Net::SSLeay::X509_VERIFY_PARAM_free($pm);
Net::SSLeay::X509_VERIFY_PARAM_free($pm2);
ok(1, 'Finishing up');
