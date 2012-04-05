use strict;
use warnings;
use Config;
use Test::More;

BEGIN {
  plan skip_all => "your perl is not compiled with ithreads or is pre-5.8" unless $Config{useithreads} && $] >= 5.008;
  require threads;
};

#XXX-TODO perhaps perl+ithreads related issue (needs more investigation)
plan skip_all => "this test sometimes crashes on cygwin" if $^O eq 'cygwin';

plan tests => 1;

use FindBin;
use Net::SSLeay;

my $start_time = time;

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

#exit the whole program if it runs too long
threads->new( sub { sleep 20; warn "FATAL: TIMEOUT!"; exit } )->detach;

#print STDERR "Gonna start multi-threading part\n";
threads->new(\&do_check) for (1..20);

#print STDERR "Waiting for all threads to finish\n";
do_sleep(50) while (threads->list());

pass("successfully finished, duration=".(time-$start_time));
exit(0);

sub do_sleep {
  my $miliseconds = shift;
  select(undef, undef, undef, $miliseconds/1000);
}

sub do_check {
  #printf STDERR ("[thread:%04d] do_check started\n", threads->tid);
  
  my $c = Net::SSLeay::CTX_new() or warn "CTX_new failed" and exit;
  my $d = Net::SSLeay::new($c) or warn "SSL_new" and exit;
  my $e = Net::SSLeay::SESSION_new() or warn "SSL_SESSION_new failed" and exit;
  Net::SSLeay::set_session($d,$e);
  Net::SSLeay::SESSION_free($e);
  Net::SSLeay::free($d);
  Net::SSLeay::CTX_free($c);
    
  #printf STDERR ("[thread:%04d] do_check finished\n", threads->tid);
  threads->detach();
}