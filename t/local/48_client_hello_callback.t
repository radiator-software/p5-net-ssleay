use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(
    can_fork data_file_path initialise_libssl new_ctx tcp_socket
);

BEGIN {
    if (not defined &Net::SSLeay::CTX_set_client_hello_cb) {
        plan skip_all => "No SSL_CTX_set_client_hello_cb()";
    } elsif (not can_fork()) {
        plan skip_all => "fork() not supported on this system";
    } else {
        plan tests => 19;
    }
}

initialise_libssl();

my $server = tcp_socket();
my $pid;

my $cert_pem = data_file_path('simple-cert.cert.pem');
my $key_pem  = data_file_path('simple-cert.key.pem');

my $cb_test_arg = [1, 'string for hello cb test arg'];

# As of 2023-08, even the latest in-development OpenSSL allows
# connections with SSLv2 ClientHello. Tested with OpenSSL 0.9.8f as
# client and OpenSSL 3.2.0-dev from git master branch as
# server. Trigger alert 42 as a marker.
sub client_hello_cb_v2hello_detection
{
    my ($ssl, $arg) = @_;

    is(Net::SSLeay::client_hello_isv2($ssl), 1, 'SSLv2 ClientHello');
    my $al = Net::SSLeay::AD_BAD_CERTIFICATE();
    return (Net::SSLeay::CLIENT_HELLO_ERROR(), $al);
}

# See that the exact same reference with unchanged contents are made
# available for the callback. Allow handshake to proceed.
sub client_hello_cb_value_passing
{
    my ($ssl, $arg) = @_;

    pass('client_hello_cb_value_passing called');
    is($cb_test_arg, $$arg, 'callback arg passed correctly');
    is_deeply($cb_test_arg, $$arg, 'callback arg contents passed correctly');
    return Net::SSLeay::CLIENT_HELLO_SUCCESS();
}

# Abort handshake with an ALPN alert. Test this on the client side.
sub client_hello_cb_alert_alpn
{
    my ($ssl, $arg) = @_;

    pass('client_hello_cb_alert_alpn called');
    my $al = Net::SSLeay::AD_NO_APPLICATION_PROTOCOL();
    return (Net::SSLeay::CLIENT_HELLO_ERROR(), $al);
}

# Check that alert is ignored with success return. Allow handshake to
# proceed.
sub client_hello_cb_conflicting_return_value
{
    my ($ssl, $arg) = @_;

    pass('client_hello_cb_conflicting_return_value called');
    my $al = Net::SSLeay::AD_NO_APPLICATION_PROTOCOL();
    return (Net::SSLeay::CLIENT_HELLO_SUCCESS(), $al);
}

# Catch incorrectly implemented callbacks. A callback can not return
# too few values
sub client_hello_cb_no_return_value
{
    my ($ssl, $arg) = @_;

    pass('client_hello_cb_no_return_value called');
    return;
}

# Catch incorrectly implemented callbacks. A callback can not return
# too many values
sub client_hello_cb_too_many_return_values
{
    my ($ssl, $arg) = @_;

    pass('client_hello_cb_too_many_return_values called');
    my $al = Net::SSLeay::AD_NO_APPLICATION_PROTOCOL();
    return (Net::SSLeay::CLIENT_HELLO_SUCCESS(), $al, 'surprise');
}

# Definitions for tests. Each array entry defines a test round with
# instructions for both TLS client and server.
my @cb_tests = (
    # SSL_client_hello_cb_fn - callback function
    # argument passed to the callback
    # true if the callback function triggers croak()
    # true if the client needs to test that ALPN alert (120) is received
    [ \&client_hello_cb_v2hello_detection, undef, 0 ],
    [ \&client_hello_cb_value_passing, \$cb_test_arg, 0 ],
    [ \&client_hello_cb_alert_alpn, undef, 0, 'alerts'],
    [ \&client_hello_cb_alert_alpn, undef, 0, 'alerts'], # Call again to increase alert counter
    [ \&client_hello_cb_conflicting_return_value, undef, 0 ],
    [ \&client_hello_cb_no_return_value, undef, 'croaks' ],
    [ \&client_hello_cb_too_many_return_values, undef, 'croaks' ],
    );

# Array that collects tests the client does. These are evaluated after
# the server has done all its tests. This is to keep the server and
# client test output from being incorrectly interleaved.
my @results;

{
    # SSL server
    $pid = fork();
    BAIL_OUT("failed to fork: $!") unless defined $pid;
    if ($pid == 0) {
	foreach my $cb_test (@cb_tests) {
	    my $ns = $server->accept();

	    my ($ctx, $proto) = new_ctx('TLSv1.2', 'TLSv1.3');
	    Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);

	    # TLSv1.3 servers send session tickets after the handshake; if a client
	    # closes the connection before the server sends the tickets, accept()
	    # fails with SSL_ERROR_SYSCALL and errno=EPIPE, which will cause this
	    # process to receive a SIGPIPE signal and exit unsuccessfully
	    Net::SSLeay::CTX_set_num_tickets($ctx, 0);

	    Net::SSLeay::CTX_set_client_hello_cb($ctx, $cb_test->[0], $cb_test->[1]);

	    my $ssl = Net::SSLeay::new($ctx);
	    Net::SSLeay::set_fd($ssl, fileno($ns));

	    # Some of test info_cbs attempt to trigger croak() which
	    # needs to be caught and tested here.
	    my $lives = eval { Net::SSLeay::accept($ssl); return 1; };
	    chomp(my $reason = $@);
	    if ($cb_test->[2])
	    {
		$lives ?
		    fail('ssl_client_hello_cb_fn did not die') :
		    like($@, qr/ssl_client_hello_cb_fn perl function returned/, "Died because of ssl_client_hello_cb_fn: $reason");
	    } else
	    {
		$lives ?
		    pass('ssl_client_hello_cb_fn did not die') :
		    fail("Died with reason: $reason");
	    }

	    Net::SSLeay::free($ssl);
	    Net::SSLeay::CTX_free($ctx);
	    close($ns) || die("server close: $!");
	}
        $server->close() || die("server listen socket close: $!");
        exit(0);
    }
}

{
    # SSL client
    my $alpn_alert_count = 0;

    # Use info callback to count TLS alert 120 occurences (ALPN alert).
    my $infocb = sub {
        my ($ssl, $where, $ret) = @_;

        if ($where & Net::SSLeay::CB_ALERT()) {
	    $alpn_alert_count++ if Net::SSLeay::alert_desc_string_long($ret) =~ m/no application protocol/s;
	}
    };

    # Start with SSLv2 ClientHello detection test. Send a canned SSLv2
    # ClientHello.
    {
	my $s_clientv2 = $server->connect();
	my $clientv2_hello = get_sslv2_hello();
	syswrite($s_clientv2, $clientv2_hello, length $clientv2_hello);
	sysread($s_clientv2, my $buf, 16384);

	# Alert (15), version (0303|4), length (0002), level fatal (02), bad cert(2a)
	push @results, [unpack('H*', $buf) =~ m/^15030.0002022a\z/, 'Alert from SSLv2 ClientHello'];
	close($s_clientv2) || die("s_clientv2 close");
	shift @cb_tests;
    }

    # The rest of tests use client's TLS stack
    foreach my $cb_test (@cb_tests) {
	my $s_c = $server->connect();

	my ($ctx_c, $proto_c) = new_ctx('TLSv1.2', 'TLSv1.3');
	Net::SSLeay::CTX_set_info_callback($ctx_c, $infocb)
	    if $cb_test->[3];

	# Add ALPN extension to ClientHello. We can then test that our
	# code finds it on the server side. We don't otherwise use
	# ALPN.
	my $rv = Net::SSLeay::CTX_set_alpn_protos($ctx_c, ['foo/1','bar/2']);

	Net::SSLeay::CTX_set_options($ctx_c, Net::SSLeay::OP_ALL());
	my $ssl_c = Net::SSLeay::new($ctx_c);
	Net::SSLeay::set_fd($ssl_c, $s_c);
	Net::SSLeay::connect($ssl_c);

	Net::SSLeay::free($ssl_c);
	Net::SSLeay::CTX_free($ctx_c);
	close($s_c) || die("client close: $!");
    }
    $server->close() || die("client listen socket close: $!");
    push @results, [$alpn_alert_count == 2, "ALPN alert count is correct: got $alpn_alert_count"];
}

waitpid $pid, 0;
push @results, [$? == 0, 'server exited with 0'];
END {
  Test::More->builder->current_test(16);
  ok( $_->[0], $_->[1] ) for (@results);
}

# Use a canned SSLv2 ClientHello for testing OpenSSL's
# SSL_client_hello_isv2()
sub get_sslv2_hello
{
    # Captures with OpenSSL 0.9.8f. The second capture uses TLSv1.0 as
    # Version but still includes a number of SSLv2 ciphersuites.
    #
    # openssl s_client -connect 127.0.0.1:443 -ssl2
    # openssl s_client -connect 127.0.0.1:443
    my $sslv2_sslv2_hex_f = '802e0100020015000000100700c00500800300800100800600400400800200808f11701ccdc4eab421b6d03e4942ea98';
    my $sslv2_tlsv1_hex_f = '807a01030100510000002000003900003800003500001600001300000a0700c000003300003200002f0000070500800300800000050000040100800000150000120000090600400000140000110000080000060400800000030200807f0913623fe5e84de01bc7733ae8fcdcefda1ef60a4c960ac7251f6560841566';

    # Captures with OpenSSL 0.9.8zh.
    #
    # The first capture is similar to 0.9.8f but the ciphersuites are
    # now ordered with the strongest first.The second capture uses
    # TLSv1.0 as Version but compared to 0.9.8f has a more modern set
    # of ciphers and includes TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
    my $sslv2_sslv2_hex_zh = '802e0100020015000000100700c006004005008004008003008002008001008015c9eb78cbf9702542ac2d4c46b6101a';
    my $sslv2_tlsv1_hex_zh = '805901030100300000002000003900003800003500001600001300000a00003300003200002f0000070000050000040000150000120000090000ff1f90dda05ec4a857523dcc0ae06c461a99c36ce647a84aa64061c054333376b9';

    return pack('H*', $sslv2_tlsv1_hex_zh);
}
