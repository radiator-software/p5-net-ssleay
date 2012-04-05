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

# NOTE: expect warnings about threads still running under perl 5.8 and threads 1.71
plan tests => 1;

use FindBin;
use File::Spec;
use Net::SSLeay;

my $start_time = time;
my $file = File::Spec->catfile('t', 'data', 'key.pem');

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

#exit the whole program if it runs too long
threads->new( sub { sleep 20; warn "FATAL: TIMEOUT!"; exit } )->detach;

#print STDERR "Gonna start main thread part\n";
my $ctx = Net::SSLeay::CTX_new() or warn "CTX_new failed" and exit;
Net::SSLeay::CTX_set_default_passwd_cb($ctx, \&callback);
Net::SSLeay::CTX_use_PrivateKey_file($ctx, $file, &Net::SSLeay::FILETYPE_PEM) or warn "CTX_use_PrivateKey_file (file=$file) failed" and exit;
Net::SSLeay::CTX_set_default_passwd_cb($ctx, undef);
Net::SSLeay::CTX_free($ctx);

#print STDERR "Gonna start multi-threading part\n";
threads->new(\&do_check) for (1..10);

#print STDERR "Waiting for all threads to finish\n";
do_sleep(50) while(threads->list());

pass("successfully finished, duration=".(time-$start_time));
exit(0);

sub callback {
  #printf STDERR ("[thread:%04d] Inside callback\n", threads->tid);
  return "secret"; # password
}

sub do_sleep {
  my $miliseconds = shift;
  select(undef, undef, undef, $miliseconds/1000);
}

sub do_check {
  #printf STDERR ("[thread:%04d] do_check started\n", threads->tid);
  
  my $c = Net::SSLeay::CTX_new() or warn "CTX_new failed" and exit;
  Net::SSLeay::CTX_set_default_passwd_cb($c, \&callback);
  Net::SSLeay::CTX_use_PrivateKey_file($c, $file, &Net::SSLeay::FILETYPE_PEM) or warn "CTX_use_PrivateKey_file (file=$file) failed" and exit;
  Net::SSLeay::CTX_set_default_passwd_cb($c, undef);
  Net::SSLeay::CTX_free($c);
  #do_sleep(rand(500));
    
  #printf STDERR ("[thread:%04d] do_check finished\n", threads->tid);
  threads->detach();
}