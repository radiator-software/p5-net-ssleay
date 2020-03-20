#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

# Starting with Net::SSLeay 1.88, the Pod syntax uses constructs that
# do not pass with older Test::Pod versions, such as 1.40 that comes
# with RHEL 6.

# Here's a snippet from Test::Pod Changes file for release 1.41:
#
# Test::Pod no longer complains about the construct L<text|url>, as it is
# no longer illegal (as of Perl 5.11.3).
my $min_test_pod = "1.41";

eval "use Test::Pod $min_test_pod";
plan skip_all => "Test::Pod $min_test_pod required for testing Pod" if $@;

all_pod_files_ok(qw(
            blib/lib/Net/SSLeay.pm
            blib/lib/Net/SSLeay/Handle.pm
));
