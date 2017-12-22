#!/usr/bin/perl
#
# Test various verify and ASN functions
# added 2010-04-16

use strict;
use warnings;
use Test::More tests => 79;
use Net::SSLeay;
use File::Spec;
use IO::Socket::INET;
use Config;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::add_ssl_algorithms();
Net::SSLeay::OpenSSL_add_all_algorithms();

# Our CA cert and a cert signed with it
my $ca_pem = File::Spec->catfile('t', 'data', 'test_CA1.crt.pem');
my $ca_dir =  File::Spec->catfile('t', 'data');
my $cert_pem = File::Spec->catfile('t', 'data', 'testcert_wildcard.crt.pem');
my $key_pem = File::Spec->catfile('t', 'data', 'testcert_key_2048.pem');

my $pm;
my $pm2;
my $verify_result = -1;

SKIP: {
  skip 'openssl-0.9.8 required', 7 unless Net::SSLeay::SSLeay >= 0x0090800f;
  $pm = Net::SSLeay::X509_VERIFY_PARAM_new();
  ok($pm, 'X509_VERIFY_PARAM_new');
  $pm2 = Net::SSLeay::X509_VERIFY_PARAM_new();
  ok($pm2, 'X509_VERIFY_PARAM_new 2');
  ok(Net::SSLeay::X509_VERIFY_PARAM_inherit($pm2, $pm), 'X509_VERIFY_PARAM_inherit');
  ok(Net::SSLeay::X509_VERIFY_PARAM_set1($pm2, $pm), 'X509_VERIFY_PARAM_inherit');
  ok(Net::SSLeay::X509_VERIFY_PARAM_set1_name($pm, 'fred'), 'X509_VERIFY_PARAM_set1_name');
  ok(Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS() == 0x40, 'X509_V_FLAG_ALLOW_PROXY_CERTS');
  ok(Net::SSLeay::X509_VERIFY_PARAM_set_flags($pm, Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS()), 'X509_VERIFY_PARAM_set_flags');
}

SKIP: {
  skip 'openssl-0.9.8a required', 3 unless Net::SSLeay::SSLeay >= 0x0090801f;
  ok(Net::SSLeay::X509_VERIFY_PARAM_get_flags($pm) == Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS(), 'X509_VERIFY_PARAM_get_flags');
  ok(Net::SSLeay::X509_VERIFY_PARAM_clear_flags($pm, Net::SSLeay::X509_V_FLAG_ALLOW_PROXY_CERTS()), 'X509_VERIFY_PARAM_clear_flags');
  ok(Net::SSLeay::X509_VERIFY_PARAM_get_flags($pm) == 0, 'X509_VERIFY_PARAM_get_flags');
};

SKIP: {
  skip 'openssl-0.9.8 required', 4 unless Net::SSLeay::SSLeay >= 0x0090800f;
  ok(Net::SSLeay::X509_PURPOSE_SSL_CLIENT() == 1, 'X509_PURPOSE_SSL_CLIENT');
  ok(Net::SSLeay::X509_VERIFY_PARAM_set_purpose($pm, Net::SSLeay::X509_PURPOSE_SSL_CLIENT()), 'X509_VERIFY_PARAM_set_purpose');
  ok(Net::SSLeay::X509_TRUST_EMAIL() == 4, 'X509_TRUST_EMAIL');
  ok(Net::SSLeay::X509_VERIFY_PARAM_set_trust($pm, Net::SSLeay::X509_TRUST_EMAIL()), 'X509_VERIFY_PARAM_set_trust');
  Net::SSLeay::X509_VERIFY_PARAM_set_depth($pm, 5);
  Net::SSLeay::X509_VERIFY_PARAM_set_time($pm, time);
  Net::SSLeay::X509_VERIFY_PARAM_free($pm);
  Net::SSLeay::X509_VERIFY_PARAM_free($pm2);
}

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
ok(Net::SSLeay::OBJ_cmp($asn_object2, $asn_object) != 0, 'OBJ_cmp');

ok(1, "Finished with tests that don't need fork");

my $server;
SKIP: {
     skip "fork() not supported on $^O", 54, unless $Config{d_fork};

     $server = IO::Socket::INET->new( LocalAddr => '127.0.0.1', Listen => 3)
	 or BAIL_OUT("failed to create server socket: $!");

     run_server();
     my $server_addr = $server->sockhost.':'.$server->sockport;
     close($server);
     client($server_addr);
}

sub test_policy_checks
{
    my ($ctx, $cl, $ok) = @_;

    $pm = Net::SSLeay::X509_VERIFY_PARAM_new();

    # Certificate must have this policy
    Net::SSLeay::X509_VERIFY_PARAM_set_flags($pm, Net::SSLeay::X509_V_FLAG_POLICY_CHECK() | Net::SSLeay::X509_V_FLAG_EXPLICIT_POLICY());

    my $oid = $ok ? '1.1.3.4' : '1.1.3.3.99.88.77';
    my $pobject = Net::SSLeay::OBJ_txt2obj($oid, 1);
    ok($pobject, "OBJ_txt2obj($oid)");
    is(Net::SSLeay::X509_VERIFY_PARAM_add0_policy($pm, $pobject), 1, "X509_VERIFY_PARAM_add0_policy($oid)");

    my $ssl = client_get_ssl($ctx, $cl, $pm);
    my $ret = Net::SSLeay::connect($ssl);
    is($verify_result, Net::SSLeay::get_verify_result($ssl), 'Verify callback result and get_verify_result are equal');
    if ($ok) {
	is($ret, 1, 'connect ok: policy checks succeeded');
	is($verify_result, Net::SSLeay::X509_V_OK(), 'Verify result is X509_V_OK');
	print "connect failed: $ret: " . Net::SSLeay::print_errs() . "\n" unless $ret == 1;
    } else {
	isnt($ret, 1, 'connect not ok: policy checks must fail') if !$ok;
	is($verify_result, Net::SSLeay::X509_V_ERR_NO_EXPLICIT_POLICY(), 'Verify result is X509_V_ERR_NO_EXPLICIT_POLICY');
    }

    Net::SSLeay::X509_VERIFY_PARAM_free($pm);
}

# Currently OpenSSL specific: even the latest LibreSSL 2.6.3 does not have these
sub test_hostname_checks
{
    my ($ctx, $cl, $ok) = @_;
  SKIP: {
      skip 'No Net::SSLeay::X509_VERIFY_PARAM_set1_host, skipping hostname_checks', 13 unless (exists &Net::SSLeay::X509_VERIFY_PARAM_set1_host);

      $pm = Net::SSLeay::X509_VERIFY_PARAM_new();

      # Note: wildcards are supported by default
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_host($pm, 'server.example.com'), 1, 'X509_VERIFY_PARAM_set1_host(server.example.com)') if $ok;
      is(Net::SSLeay::X509_VERIFY_PARAM_add1_host($pm, 'server.not.example.com'), 1, 'X509_VERIFY_PARAM_add1_host(server.not.example.com)') if !$ok;

      is(Net::SSLeay::X509_VERIFY_PARAM_set1_email($pm, 'wildcard@example.com'), 1, 'X509_VERIFY_PARAM_set1_email');

      # Note: 'set' means that only one successfully set can be active
      # set1_ip:      IPv4 or IPv6 address as 4 or 16 octet binary.
      # setip_ip_asc: IPv4 or IPv6 address as ASCII string
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip($pm, pack('CCCC', 10, 20, 30, 40)), 1, 'X509_VERIFY_PARAM_set1_ip(10.20.30.40)');
#      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip($pm, pack('NNNN', hex('20010db8'), hex('01480100'), 0, hex('31'))), 1, 'X509_VERIFY_PARAM_set1_ip(2001:db8:148:100::31)');
#      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip_asc($pm, '10.20.30.40'), 1, 'X509_VERIFY_PARAM_set1_ip_asc(10.20.30.40)');
#      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip_asc($pm, '2001:db8:148:100::31'), 1, 'X509_VERIFY_PARAM_set1_ip_asc(2001:db8:148:100::31))');

      # Also see that incorrect values do not change anything.
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip($pm, '123'),              0, 'X509_VERIFY_PARAM_set1_ip(123)');
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip($pm, '123456789012345'),  0, 'X509_VERIFY_PARAM_set1_ip(123456789012345)');
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip_asc($pm, '10.20.30.256'), 0, 'X509_VERIFY_PARAM_set1_ip_asc(10.20.30.256)');
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_ip_asc($pm, '12345::'),      0, 'X509_VERIFY_PARAM_set1_ip_asc(12345::)');

      my $ssl = client_get_ssl($ctx, $cl, $pm);
      my $ret = Net::SSLeay::connect($ssl);
      is($verify_result, Net::SSLeay::get_verify_result($ssl), 'Verify callback result and get_verify_result are equal');
      if ($ok) {
	  is($ret, 1, 'connect ok: hostname checks succeeded');
	  is($verify_result, Net::SSLeay::X509_V_OK(), 'Verify result is X509_V_OK');
	  print "connect failed: $ret: " . Net::SSLeay::print_errs() . "\n" unless $ret == 1;
      } else {
	  isnt($ret, 1, 'connect not ok: hostname checks must fail') if !$ok;
	  is($verify_result, Net::SSLeay::X509_V_ERR_HOSTNAME_MISMATCH(), 'Verify result is X509_V_ERR_HOSTNAME_MISMATCH');
      }

      # For some reason OpenSSL 1.0.2 returns undef for get0_peername. Are we doing this wrong?
      $pm2 = Net::SSLeay::get0_param($ssl);
      my $peername = Net::SSLeay::X509_VERIFY_PARAM_get0_peername($pm2);
      is($peername, '*.example.com', 'X509_VERIFY_PARAM_get0_peername returns *.example.com')     if ($ok && Net::SSLeay::SSLeay >= 0x10100000);
      is($peername, undef, 'X509_VERIFY_PARAM_get0_peername returns undefined for OpenSSL 1.0.2') if ($ok && Net::SSLeay::SSLeay <  0x10100000);
      is($peername, undef, 'X509_VERIFY_PARAM_get0_peername returns undefined') if !$ok;

      Net::SSLeay::X509_VERIFY_PARAM_free($pm);
      Net::SSLeay::X509_VERIFY_PARAM_free($pm2);
    }
}

sub test_wildcard_checks
{
    my ($ctx, $cl) = @_;
  SKIP: {
      skip 'No Net::SSLeay::X509_VERIFY_PARAM_set1_host, skipping wildcard_checks', 7 unless (exists &Net::SSLeay::X509_VERIFY_PARAM_set1_host);

      $pm = Net::SSLeay::X509_VERIFY_PARAM_new();

      # Wildcards are allowed by default: disallow
      is(Net::SSLeay::X509_VERIFY_PARAM_set1_host($pm, 'www.example.com'), 1, 'X509_VERIFY_PARAM_set1_host');
      is(Net::SSLeay::X509_VERIFY_PARAM_set_hostflags($pm, Net::SSLeay::X509_CHECK_FLAG_NO_WILDCARDS()), undef, 'X509_VERIFY_PARAM_set_hostflags(X509_CHECK_FLAG_NO_WILDCARDS)');

      my $ssl = client_get_ssl($ctx, $cl, $pm);
      my $ret = Net::SSLeay::connect($ssl);
      isnt($ret, 1, 'Connect must fail in wildcard test');
      is($verify_result, Net::SSLeay::get_verify_result($ssl), 'Verify callback result and get_verify_result are equal');
      is($verify_result, Net::SSLeay::X509_V_ERR_HOSTNAME_MISMATCH(), 'Verify result is X509_V_ERR_HOSTNAME_MISMATCH');

      Net::SSLeay::X509_VERIFY_PARAM_free($pm);
    }
}

# Prepare and return a new $ssl based on callers verification needs
# Note that this adds tests to caller's test count.
sub client_get_ssl
{
    my ($ctx, $cl, $pm) = @_;

    my $store = Net::SSLeay::CTX_get_cert_store($ctx);
    ok($store, 'CTX_get_cert_store');
    is(Net::SSLeay::X509_STORE_set1_param($store, $pm), 1, 'X509_STORE_set1_param');

    # Needs OpenSSL 1.0.0 or later
    #Net::SSLeay::CTX_set1_param($ctx, $pm);

    $verify_result = -1; # Last verification result, set by callback below
    my $verify_cb = sub { $verify_result = Net::SSLeay::X509_STORE_CTX_get_error($_[1]); return $_[0];};

    my $ssl = Net::SSLeay::new($ctx);
    Net::SSLeay::set_verify($ssl, Net::SSLeay::VERIFY_PEER(), $verify_cb);
    Net::SSLeay::set_fd($ssl, $cl);

    return $ssl;
}

# SSL client - connect to server and test different verification
# settings
sub client {
    my ($server_addr) = @_;

    my ($ctx, $cl);
    foreach my $task (qw(
		      policy_checks_ok policy_checks_fail
		      hostname_checks_ok hostname_checks_fail
		      wildcard_checks
		      finish))
    {
	$ctx = Net::SSLeay::CTX_new();
	is(Net::SSLeay::CTX_load_verify_locations($ctx, $ca_pem, $ca_dir), 1, "load_verify_locations($ca_pem $ca_dir)");

	$cl = IO::Socket::INET->new($server_addr) or BAIL_OUT("failed to connect to server: $!");

	test_policy_checks($ctx, $cl, 1)   if $task eq 'policy_checks_ok';
	test_policy_checks($ctx, $cl, 0)   if $task eq 'policy_checks_fail';
	test_hostname_checks($ctx, $cl, 1) if $task eq 'hostname_checks_ok';
	test_hostname_checks($ctx, $cl, 0) if $task eq 'hostname_checks_fail';
	test_wildcard_checks($ctx, $cl) if $task eq 'wildcard_checks';
	last if $task eq 'finish'; # Leaves $cl alive

	close($cl);
    }

    # Tell the server to quit and see that our connection is still up
    $ctx = Net::SSLeay::CTX_new();
    my $ssl = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, $cl);
    Net::SSLeay::connect($ssl);
    my $end = "end";
    Net::SSLeay::write($ssl, $end);
    ok($end eq Net::SSLeay::read($ssl),  'Successful termination');
    return;
}

# SSL server - just accept connnections and exit when told to by
# the client
sub run_server
{
    my $pid;
    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");

    return if $pid != 0;

    my $ctx = Net::SSLeay::CTX_new();
    Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
    my $ret = Net::SSLeay::CTX_check_private_key($ctx);
    BAIL_OUT("Server: CTX_check_private_key failed: $cert_pem, $key_pem") unless $ret == 1;

    while (1)
    {
	my $cl = $server->accept or BAIL_OUT("accept failed: $!");
	my $ssl = Net::SSLeay::new($ctx);

	Net::SSLeay::set_fd($ssl, fileno($cl));
	my $ret = Net::SSLeay::accept($ssl);
	next unless $ret == 1;

	# Termination request or other message from client
	my $msg = Net::SSLeay::read($ssl);
	if ($msg eq 'end')
	{
	    Net::SSLeay::write($ssl, 'end');
	    exit (0);
	}
    }
}
