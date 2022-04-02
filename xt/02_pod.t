# Ensure all pod-formatted documentation is valid

use lib 'inc';

use Test::Net::SSLeay;

use Test::Pod;

all_pod_files_ok(
    qw(
        blib/lib/Net/SSLeay.pm
        blib/lib/Net/SSLeay/Handle.pm
        helper_script/generate-test-pki
        inc/Test/Net/SSLeay.pm
        inc/Test/Net/SSLeay/Socket.pm
    )
);
