#!/usr/bin/perl

# Various session related tests. Currently:
# - SSL_CTX_sess_set_get_cb and related functions

use strict;
use warnings;
use Test::More;
use Socket;
use File::Spec;
use Net::SSLeay;
use Config;
use IO::Socket::INET;
use Storable;

BEGIN {
  plan skip_all => "fork() not supported on $^O" unless $Config{d_fork};
}

my $tests = 58;
plan tests => $tests;

my $pid;
alarm(30);
END { kill 9,$pid if $pid }

# The -end round is just for communicating stats back to client
my @rounds = qw(TLSv1 TLSv1.1 TLSv1.2 TLSv1.3 TLSv1.3-num-tickets-ssl TLSv1.3-num-tickets-ctx-6 TLSv1.3-num-tickets-ctx-0 TLSv1-end);
my (%server_stats, %client_stats);

# Update client and server stats so that when something fails, it
# remains in failed state
sub set_client_stat
{
    my ($round, $param, $is_ok) = @_;

    if ($is_ok) {
	$client_stats{$round}->{$param} = 1 unless defined $client_stats{$round}->{$param};
	return;
    }
    $client_stats{$round}->{$param} = 0;
}

sub set_server_stat
{
    my ($round, $param, $is_ok) = @_;

    if ($is_ok) {
	$server_stats{$round}->{$param} = 1 unless defined $server_stats{$round}->{$param};
	return;
    }
    $server_stats{$round}->{$param} = 0;
}

# Separate session callbacks for client and server. The callbacks
# update stats and check that SSL_CTX, SSL and SESSION are as
# expected.
sub client_new_cb
{
    my ($ssl, $ssl_session, $expected_ctx, $round) = @_;

    $client_stats{$round}->{new_cb_called}++;

    my $ctx = Net::SSLeay::get_SSL_CTX($ssl);
    my $ssl_version = Net::SSLeay::get_version($ssl);
    my $is_ok = ($ctx eq $expected_ctx &&
		 $ssl_session eq Net::SSLeay::SSL_get0_session($ssl) &&
		 $round =~ m/^$ssl_version/);
    diag("client_new_cb params not ok: $round") unless $is_ok;
    set_client_stat($round, 'new_params_ok', $is_ok);

    if (defined &Net::SSLeay::SESSION_is_resumable) {
	my $is_resumable = Net::SSLeay::SESSION_is_resumable($ssl_session);
	BAIL_OUT("is_resumable is not 0 or 1: $round") unless defined $is_resumable && ($is_resumable == 0 || $is_resumable == 1);
	set_client_stat($round, 'new_session_is_resumable', $is_resumable);
    }

    #Net::SSLeay::SESSION_print_fp(*STDOUT, $ssl_session);
    return 0;
}

sub client_remove_cb
{
    my ($ctx, $ssl_session, $expected_ctx, $round) = @_;

    $client_stats{$round}->{remove_cb_called}++;

    my $is_ok = ($ctx eq $expected_ctx);
    diag("client_remove_cb params not ok: $round") unless $is_ok;
    set_client_stat($round, 'remove_params_ok', $is_ok);

    #Net::SSLeay::SESSION_print_fp(*STDOUT, $ssl_session);
    return;
}

sub server_new_cb
{
    my ($ssl, $ssl_session, $expected_ctx, $round) = @_;

    $server_stats{$round}->{new_cb_called}++;

    my $ctx = Net::SSLeay::get_SSL_CTX($ssl);
    my $ssl_version = Net::SSLeay::get_version($ssl);
    my $is_ok = ($ctx eq $expected_ctx &&
		 $ssl_session eq Net::SSLeay::SSL_get0_session($ssl) &&
		 $round =~ m/^$ssl_version/);
    diag("server_new_cb params not ok: $round") unless $is_ok;
    set_server_stat($round, 'new_params_ok', $is_ok);

    if (defined &Net::SSLeay::SESSION_is_resumable) {
	my $is_resumable = Net::SSLeay::SESSION_is_resumable($ssl_session);
	BAIL_OUT("is_resumable is not 0 or 1: $round") unless defined $is_resumable && ($is_resumable == 0 || $is_resumable == 1);
	set_server_stat($round, 'new_session_is_resumable', $is_resumable);
    }

    #Net::SSLeay::SESSION_print_fp(*STDOUT, $ssl_session);
    return 0;
}

sub server_remove_cb
{
    my ($ctx, $ssl_session, $expected_ctx, $round) = @_;

    $server_stats{$round}->{remove_cb_called}++;

    my $is_ok = ($ctx eq $expected_ctx);
    diag("server_remove_cb params not ok: $round") unless $is_ok;
    set_server_stat($round, 'remove_params_ok', $is_ok);

    return;
}

my ($server, $server_ctx, $client_ctx, $server_ssl, $client_ssl);
Net::SSLeay::initialize();

# Helper for client and server
sub make_ctx
{
    my ($round) = @_;

    my $ctx;
    if ($round =~ /^TLSv1\.3/) {
	return undef unless eval { Net::SSLeay::TLS1_3_VERSION(); };

	# Use API introduced in OpenSSL 1.1.0
	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLS_method());
	Net::SSLeay::CTX_set_min_proto_version($ctx, Net::SSLeay::TLS1_3_VERSION());
	Net::SSLeay::CTX_set_max_proto_version($ctx, Net::SSLeay::TLS1_3_VERSION());
    }
    elsif ($round =~ /^TLSv1\.2/) {
	return undef unless exists &Net::SSLeay::TLSv1_2_method;

	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_2_method());
    }
    elsif ($round =~ /^TLSv1\.1/) {
	return undef unless exists &Net::SSLeay::TLSv1_1_method;

	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_1_method());
    }
    else
    {
	$ctx = Net::SSLeay::CTX_new_with_method(Net::SSLeay::TLSv1_method());
    }

    return $ctx;
}

sub server
{
    # SSL server - just handle connections, send information to
    # client and exit
    my $cert_pem = File::Spec->catfile('t', 'data', 'testcert_wildcard.crt.pem');
    my $key_pem = File::Spec->catfile('t', 'data', 'testcert_key_2048.pem');

    $server = IO::Socket::INET->new( LocalAddr => '127.0.0.1', Listen => 3)
	or BAIL_OUT("failed to create server socket: $!");

    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");
    if ($pid == 0) {
	my ($ctx, $ssl, $ret, $cl);

	foreach my $round (@rounds)
	{
	    $cl = $server->accept or BAIL_OUT("accept failed: $!");

	    $ctx = make_ctx($round);
	    next unless $ctx;

	    Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
	    Net::SSLeay::CTX_set_session_cache_mode($ctx, Net::SSLeay::SESS_CACHE_SERVER());
	    # Need OP_NO_TICKET to enable server side (Session ID based) resumption.
	    # See also SSL_CTX_set_options documenation about its use with TLSv1.3
	    Net::SSLeay::CTX_set_options($ctx, Net::SSLeay::OP_ALL() | Net::SSLeay::OP_NO_TICKET())
		if ($round !~ /^TLSv1\.3/);

	    Net::SSLeay::CTX_sess_set_new_cb($ctx, sub {server_new_cb(@_, $ctx, $round);});
	    Net::SSLeay::CTX_sess_set_remove_cb($ctx, sub {server_remove_cb(@_, $ctx, $round);});

	    # Test set_num_tickets separately for CTX and SSL
	    if (defined &Net::SSLeay::CTX_set_num_tickets)
	    {
		Net::SSLeay::CTX_set_num_tickets($ctx, 6) if ($round eq 'TLSv1.3-num-tickets-ctx-6');
		Net::SSLeay::CTX_set_num_tickets($ctx, 0) if ($round eq 'TLSv1.3-num-tickets-ctx-0');
		$server_stats{$round}->{get_num_tickets} = Net::SSLeay::CTX_get_num_tickets($ctx);
	    }

	    $ssl = Net::SSLeay::new($ctx);
	    if (defined &Net::SSLeay::set_num_tickets)
	    {
		Net::SSLeay::set_num_tickets($ssl, 4) if ($round eq 'TLSv1.3-num-tickets-ssl');
		$server_stats{$round}->{get_num_tickets} = Net::SSLeay::get_num_tickets($ssl);
	    }
	    Net::SSLeay::set_fd($ssl, fileno($cl));
	    Net::SSLeay::accept($ssl);

	    Net::SSLeay::write($ssl, "msg from server: $round");
	    my $end = Net::SSLeay::read($ssl);
	    #print "client said: $end\n";
	    if ($end eq 'end')
	    {
		Net::SSLeay::write($ssl, $end);
		Net::SSLeay::write($ssl, Storable::freeze(\%server_stats));
	    }
	    Net::SSLeay::shutdown($ssl);
	    my $sess = Net::SSLeay::get1_session($ssl);
	    $ret = Net::SSLeay::CTX_remove_session($ctx, $sess);

	    if (defined &Net::SSLeay::SESSION_is_resumable) {
		my $is_resumable = Net::SSLeay::SESSION_is_resumable($sess);
		BAIL_OUT("is_resumable is not 0 or 1: $round") unless defined $is_resumable && ($is_resumable == 0 || $is_resumable == 1);
		set_server_stat($round, 'old_session_is_resumable', $is_resumable);
	    }

	    Net::SSLeay::SESSION_free($sess) unless $ret; # Not cached, undo get1
	    Net::SSLeay::free($ssl);
	}
	#use Data::Dumper; print "Server:\n" . Dumper(\%server_stats);
	exit(0);
    }
}

sub client {
    # SSL client - connect to server and receive information that we
    # compare to our expected values

    my $saddr = $server->sockhost.':'.$server->sockport;
    my ($ctx, $ssl, $ret, $cl);
    my $end = "end";

    foreach my $round (@rounds)
    {
	$cl = IO::Socket::INET->new($saddr)
	    or BAIL_OUT("failed to connect to server: $!");

	$ctx = make_ctx($round);
	next unless $ctx;

	Net::SSLeay::CTX_set_session_cache_mode($ctx, Net::SSLeay::SESS_CACHE_CLIENT());
        Net::SSLeay::CTX_set_options($ctx, Net::SSLeay::OP_ALL());
	Net::SSLeay::CTX_sess_set_new_cb($ctx, sub {client_new_cb(@_, $ctx, $round);});
	Net::SSLeay::CTX_sess_set_remove_cb($ctx, sub {client_remove_cb(@_, $ctx, $round);});
	$ssl = Net::SSLeay::new($ctx);

	Net::SSLeay::set_fd($ssl, $cl);
	Net::SSLeay::connect($ssl);
	my $msg = Net::SSLeay::read($ssl);
	#print "server said: $msg\n";
	if ($round =~ /end/)
	{
	    Net::SSLeay::write($ssl, $end);
	    last;
	}

	Net::SSLeay::write($ssl, "continue");
	my $sess = Net::SSLeay::get1_session($ssl);
	$ret = Net::SSLeay::CTX_remove_session($ctx, $sess);
	Net::SSLeay::SESSION_free($sess) unless $ret; # Not cached, undo get1

	if (defined &Net::SSLeay::SESSION_is_resumable) {
	    my $is_resumable = Net::SSLeay::SESSION_is_resumable($sess);
	    BAIL_OUT("is_resumable is not 0 or 1: $round") unless defined $is_resumable && ($is_resumable == 0 || $is_resumable == 1);
	    set_client_stat($round, 'old_session_is_resumable', $is_resumable);
	}

	Net::SSLeay::shutdown($ssl);
	Net::SSLeay::free($ssl);
    }

    # Server should have acked our end request. Also see that our connection is still up
    my $server_end = Net::SSLeay::read($ssl);
    is($server_end, $end, "Successful termination");

    # Stats from server
    my $server_stats_ref = Storable::thaw(Net::SSLeay::read($ssl));

    my $sess = Net::SSLeay::get1_session($ssl);
    $ret = Net::SSLeay::CTX_remove_session($ctx, $sess);
    Net::SSLeay::SESSION_free($sess) unless $ret; # Not cached, undo get1
    Net::SSLeay::shutdown($ssl);
    Net::SSLeay::free($ssl);

    test_stats($server_stats_ref, \%client_stats);

    return;
}

sub test_stats
{
    my ($srv_stats, $clt_stats) = @_;

    is($srv_stats->{'TLSv1'}->{new_cb_called}, 1, 'Server TLSv1 new_cb call count');
    is($srv_stats->{'TLSv1'}->{new_params_ok}, 1, 'Server TLSv1 new_cb params were correct');
    is($srv_stats->{'TLSv1'}->{remove_cb_called}, 1, 'Server TLSv1 remove_cb call count');
    is($srv_stats->{'TLSv1'}->{remove_params_ok}, 1, 'Server TLSv1 remove_cb params were correct');

    is($clt_stats->{'TLSv1'}->{new_cb_called}, 1, 'Client TLSv1 new_cb call count');
    is($clt_stats->{'TLSv1'}->{new_params_ok}, 1, 'Client TLSv1 new_cb params were correct');
    is($clt_stats->{'TLSv1'}->{remove_cb_called}, 1, 'Client TLSv1 remove_cb call count');
    is($clt_stats->{'TLSv1'}->{remove_params_ok}, 1, 'Client TLSv1 remove_cb params were correct');

    if (defined &Net::SSLeay::SESSION_is_resumable) {
	is($srv_stats->{'TLSv1'}->{new_session_is_resumable}, 1, 'Server TLSv1 session is resumable');
	is($srv_stats->{'TLSv1'}->{old_session_is_resumable}, 0, 'Server TLSv1 session is no longer resumable');

	is($clt_stats->{'TLSv1'}->{new_session_is_resumable}, 1, 'Client TLSv1 session is resumable');
	is($clt_stats->{'TLSv1'}->{old_session_is_resumable}, 0, 'Client TLSv1 session is no longer resumable');
    } else {
      SKIP: {
	  skip('Do not have Net::SSLeay::SESSION_is_resumable', 4);
	}
    }

    if (exists &Net::SSLeay::TLSv1_1_method)
    {
	# Should be the same as TLSv1
	is($srv_stats->{'TLSv1.1'}->{new_cb_called}, 1, 'Server TLSv1.1 new_cb call count');
	is($srv_stats->{'TLSv1.1'}->{new_params_ok}, 1, 'Server TLSv1.1 new_cb params were correct');
	is($srv_stats->{'TLSv1.1'}->{remove_cb_called}, 1, 'Server TLSv1.1 remove_cb call count');
	is($srv_stats->{'TLSv1.1'}->{remove_params_ok}, 1, 'Server TLSv1.1 remove_cb params were correct');
	if (defined &Net::SSLeay::SESSION_is_resumable) {
	    is($srv_stats->{'TLSv1.1'}->{new_session_is_resumable}, 1, 'Server TLSv1.1 session is resumable');
	    is($srv_stats->{'TLSv1.1'}->{old_session_is_resumable}, 0, 'Server TLSv1.1 session is no longer resumable');

	    is($clt_stats->{'TLSv1.1'}->{new_session_is_resumable}, 1, 'Client TLSv1.1 session is resumable');
	    is($clt_stats->{'TLSv1.1'}->{old_session_is_resumable}, 0, 'Client TLSv1.1 session is no longer resumable');
	} else {
	  SKIP: {
	      skip('Do not have Net::SSLeay::SESSION_is_resumable', 4);
	    }
	}

	is($clt_stats->{'TLSv1.1'}->{new_cb_called}, 1, 'Client TLSv1.1 new_cb call count');
	is($clt_stats->{'TLSv1.1'}->{new_params_ok}, 1, 'Client TLSv1.1 new_cb params were correct');
	is($clt_stats->{'TLSv1.1'}->{remove_cb_called}, 1, 'Client TLSv1.1 remove_cb call count');
	is($clt_stats->{'TLSv1.1'}->{remove_params_ok}, 1, 'Client TLSv1.1 remove_cb params were correct');
    } else {
      SKIP: {
	  skip('Do not have support for TLSv1.1', 12);
	}
    }

    if (exists &Net::SSLeay::TLSv1_2_method)
    {
	# Should be the same as TLSv1
	is($srv_stats->{'TLSv1.2'}->{new_cb_called}, 1, 'Server TLSv1.2 new_cb call count');
	is($srv_stats->{'TLSv1.2'}->{new_params_ok}, 1, 'Server TLSv1.2 new_cb params were correct');
	is($srv_stats->{'TLSv1.2'}->{remove_cb_called}, 1, 'Server TLSv1.2 remove_cb call count');
	is($srv_stats->{'TLSv1.2'}->{remove_params_ok}, 1, 'Server TLSv1.2 remove_cb params were correct');
	if (defined &Net::SSLeay::SESSION_is_resumable) {
	    is($srv_stats->{'TLSv1.2'}->{new_session_is_resumable}, 1, 'Server TLSv1.2 session is resumable');
	    is($srv_stats->{'TLSv1.2'}->{old_session_is_resumable}, 0, 'Server TLSv1.2 session is no longer resumable');

	    is($clt_stats->{'TLSv1.2'}->{new_session_is_resumable}, 1, 'Client TLSv1.2 session is resumable');
	    is($clt_stats->{'TLSv1.2'}->{old_session_is_resumable}, 0, 'Client TLSv1.2 session is no longer resumable');
	} else {
	  SKIP: {
	      skip('Do not have Net::SSLeay::SESSION_is_resumable', 4);
	    }
	}

	is($clt_stats->{'TLSv1.2'}->{new_cb_called}, 1, 'Client TLSv1.2 new_cb call count');
	is($clt_stats->{'TLSv1.2'}->{new_params_ok}, 1, 'Client TLSv1.2 new_cb params were correct');
	is($clt_stats->{'TLSv1.2'}->{remove_cb_called}, 1, 'Client TLSv1.2 remove_cb call count');
	is($clt_stats->{'TLSv1.2'}->{remove_params_ok}, 1, 'Client TLSv1.2 remove_cb params were correct');
    } else {
      SKIP: {
	  skip('Do not have support for TLSv1.2', 12);
	}
    }

    if (eval { Net::SSLeay::TLS1_3_VERSION(); })
    {
	# OpenSSL sends two session tickets by default: new_cb called two times
	is($srv_stats->{'TLSv1.3'}->{new_cb_called}, 2, 'Server TLSv1.3 new_cb call count');
	is($srv_stats->{'TLSv1.3'}->{new_params_ok}, 1, 'Server TLSv1.3 new_cb params were correct');
	is($srv_stats->{'TLSv1.3'}->{remove_cb_called}, 1, 'Server TLSv1.3 remove_cb call count');
	is($srv_stats->{'TLSv1.3'}->{remove_params_ok}, 1, 'Server TLSv1.3 remove_cb params were correct');
	is($srv_stats->{'TLSv1.3-num-tickets-ssl'}->{get_num_tickets}, 4, 'Server TLSv1.3 get_num_tickets 4');
	is($srv_stats->{'TLSv1.3-num-tickets-ssl'}->{new_cb_called}, 4, 'Server TLSv1.3 new_cb call count with set_num_tickets 4');
	is($srv_stats->{'TLSv1.3-num-tickets-ctx-6'}->{get_num_tickets}, 6, 'Server TLSv1.3 CTX_get_num_tickets 6');
	is($srv_stats->{'TLSv1.3-num-tickets-ctx-6'}->{new_cb_called}, 6, 'Server TLSv1.3 new_cb call count with CTX_set_num_tickets 6');
	is($srv_stats->{'TLSv1.3-num-tickets-ctx-0'}->{get_num_tickets}, 0, 'Server TLSv1.3 CTX_get_num_tickets 0');
	is($srv_stats->{'TLSv1.3-num-tickets-ctx-0'}->{new_cb_called}, undef, 'Server TLSv1.3 new_cb call count with CTX_set_num_tickets 0');
	is($srv_stats->{'TLSv1.3'}->{new_session_is_resumable}, 1, 'Server TLSv1.3 session is resumable');
	is($srv_stats->{'TLSv1.3'}->{old_session_is_resumable}, 0, 'Server TLSv1.3 session is no longer resumable');

	is($clt_stats->{'TLSv1.3'}->{new_cb_called}, 2, 'Client TLSv1.3 new_cb call count');
	is($clt_stats->{'TLSv1.3'}->{new_params_ok}, 1, 'Client TLSv1.3 new_cb params were correct');
	is($clt_stats->{'TLSv1.3'}->{remove_cb_called}, 1, 'Client TLSv1.3 remove_cb call count');
	is($clt_stats->{'TLSv1.3'}->{remove_params_ok}, 1, 'Client TLSv1.3 remove_cb params were correct');
	is($clt_stats->{'TLSv1.3-num-tickets-ssl'}->{new_cb_called}, 4, 'Client TLSv1.3 new_cb call count with set_num_tickets 4');
	is($clt_stats->{'TLSv1.3-num-tickets-ctx-6'}->{new_cb_called}, 6, 'Client TLSv1.3 new_cb call count with CTX_set_num_tickets 6');
	is($clt_stats->{'TLSv1.3-num-tickets-ctx-0'}->{new_cb_called}, undef, 'Client TLSv1.3 new_cb call count with CTX_set_num_tickets 0');
	is($clt_stats->{'TLSv1.3'}->{new_session_is_resumable}, 1, 'Client TLSv1.3 session is resumable');
	is($clt_stats->{'TLSv1.3'}->{old_session_is_resumable}, 0, 'Client TLSv1.3 session is no longer resumable');
    } else {
      SKIP: {
	  skip('Do not have support for TLSv1.3', 21);
	}
    }

    #  use Data::Dumper; print "Server:\n" . Dumper(\%srv_stats);
    #  use Data::Dumper; print "Client:\n" . Dumper(\%clt_stats);
}

server();
client();
waitpid $pid, 0;
exit(0);
