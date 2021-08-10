use lib 'inc';

use Net::SSLeay;
use Test::Net::SSLeay qw(
    can_fork data_file_path initialise_libssl new_ctx tcp_socket
);

if (not can_fork()) {
    plan skip_all => "fork() not supported on this system";
} else {
    plan tests => 2;
}

initialise_libssl();

my $pid;
alarm(30);
END { kill 9,$pid if $pid }

my $server = tcp_socket();

{
    # SSL server - just handle single connect and  shutdown connection
    my $cert_pem = data_file_path('simple-cert.cert.pem');
    my $key_pem  = data_file_path('simple-cert.key.pem');

    defined($pid = fork()) or BAIL_OUT("failed to fork: $!");
    if ($pid == 0) {
	for(qw(ctx ssl)) {
	    my $cl = $server->accept();
	    my $ctx = new_ctx();
	    Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem);
	    my $ssl = Net::SSLeay::new($ctx);
	    Net::SSLeay::set_fd($ssl, fileno($cl));
	    Net::SSLeay::accept($ssl);
	    for(1,2) {
		last if Net::SSLeay::shutdown($ssl)>0;
	    }
	    close($cl) || die("server close: $!");
	}
	$server->close() || die("server listen socket close: $!");
        exit;
    }
}

sub client {
    my ($where,$expect) = @_;
    # SSL client - connect and shutdown, all the while getting state updates
    #  with info callback

    my @states;
    my $infocb = sub {
	my ($ssl,$write_p,$version,$content_type,$buf,$len) = @_;
    $buf = unpack("H*", $buf);
	push @states,[$write_p,$version,$content_type,$len];
    };

    my $cl = $server->connect();
    my $ctx = new_ctx();
    Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
    Net::SSLeay::CTX_set_msg_callback($ctx, $infocb) if $where eq 'ctx';
    my $ssl = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, $cl);
    Net::SSLeay::set_msg_callback($ssl, $infocb) if $where eq 'ssl';
    Net::SSLeay::connect($ssl);
    for(1,2) {
	last if Net::SSLeay::shutdown($ssl)>0;
    }
    close($cl) || die("client close: $!");

    is_deeply(\@states, [
    [1,0,256,5],[1,772,22,210],[0,0,256,5],[0,772,22,122],[0,0,256,5],[0,0,256,5],[0,772,257,1],[0,772,22,6],[0,0,256,5],[0,772,257,1],[0,772,22,905],[0,0,256,5],[0,772,257,1],[0,772,22,264],[0,0,256,5],[0,772,257,1],[0,772,22,52],[1,0,256,5],[1,772,20,1],[1,0,256,5],[1,772,257,1],[1,772,22,52],[1,0,256,5],[1,772,257,1],[1,772,21,2],[0,0,256,5],[0,772,257,1],[0,772,22,217],[0,0,256,5],[0,772,257,1],[0,772,22,217],[0,0,256,5],[0,772,257,1],[0,772,21,2]
    ], "state ok");
}

client('ctx');
client('ssl');
$server->close() || die("client listen socket close: $!");
waitpid $pid, 0;

