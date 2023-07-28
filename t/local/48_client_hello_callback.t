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
        plan tests => 16;
    }
}

initialise_libssl();

my $server = tcp_socket();
my $pid;

my $cert_pem = data_file_path('simple-cert.cert.pem');
my $key_pem  = data_file_path('simple-cert.key.pem');

my $cb_test_arg = [1, 'string for hello cb test arg'];

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
    my $alpn_alert_count = 0;

    # Use info callback to count TLS alert 120 occurences (ALPN alert).
    my $infocb = sub {
        my ($ssl, $where, $ret) = @_;

        if ($where & Net::SSLeay::CB_ALERT()) {
	    $alpn_alert_count++ if Net::SSLeay::alert_desc_string_long($ret) =~ m/no application protocol/s;
	}
    };

    # SSL client
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
  Test::More->builder->current_test(14);
  ok( $_->[0], $_->[1] ) for (@results);
}
