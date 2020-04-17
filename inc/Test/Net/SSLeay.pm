package Test::Net::SSLeay;

use 5.008001;
use strict;
use warnings;
use base qw(Exporter);

use Carp qw(croak);
use English qw( $EVAL_ERROR -no_match_vars );

our $VERSION = '1.89_01';

our @EXPORT_OK = qw();

sub import {
    my ( $class, @imports ) = @_;

    # Enable strict and warnings in the caller
    strict->import;
    warnings->import;

    # Import common modules into the caller's namespace
    my $caller = caller;
    for (qw(Test::More)) {
        eval "package $caller; use $_; 1;" or croak $EVAL_ERROR;
    }

    # Import requested Test::Net::SSLeay symbols into the caller's namespace
    __PACKAGE__->export_to_level( 1, $class, @imports );

    return 1;
}

1;

__END__

=head1 NAME

Test::Net::SSLeay - Helper module for the Net-SSLeay test suite

=head1 VERSION

This document describes version 1.89_01 of Test::Net::SSLeay.

=head1 SYNOPSIS

In a Net-SSLeay test script:

    # Optional summary of the purpose of the tests in this script

    use lib 'inc';

    use Net::SSLeay;        # if required by the tests
    use Test::Net::SSLeay;  # also importing helper functions if required

    # Imports of other modules specific to this test script

    # Plan tests, or skip them altogether if certain preconditions aren't met
    if (disqualifying_condition) {
        plan skip_all => ...;
    } else {
        plan tests => ...;
    }

    # One or more Test::More-based tests

=head1 DESCRIPTION

This is a helper module that makes it easier (or, at least, less repetitive)
to write test scripts for the Net-SSLeay test suite. For consistency, all test
scripts should import this module and follow the preamble structure given in
L</SYNOPSIS>.

Importing this module has the following effects on the caller, regardless of
whether any exports are requested:

=over 4

=item *

C<strict> and C<warnings> are enabled;

=item *

L<Test::More|Test::More>, the test framework used by the Net-SSLeay test
suite, is imported.

=back

No symbols are exported by default. If desired, individual helper functions
may be imported into the caller's namespace by specifying their name in the
import list; see L</"HELPER FUNCTIONS"> for a list of available helper
functions.

=head1 HELPER FUNCTIONS

None implemented yet.

=head1 BUGS

If you encounter a problem with this module that you believe is a bug, please
report it in one of the following ways:

=over 4

=item *

create a new issue under the
L<Net-SSLeay GitHub project|https://github.com/radiator-software/p5-net-ssleay/issues/new>;

=item *

open a ticket using the
L<CPAN RT bug tracker's web interface|https://rt.cpan.org/Public/Bug/Report.html?Queue=Net-SSLeay>;

=item *

send an email to the
L<CPAN RT bug tracker's bug-reporting system|mailto:bug-Net-SSLeay@rt.cpan.org>.

=back

Please make sure your bug report includes the following information:

=over

=item *

the code you are trying to run (ideally a minimum working example that
reproduces the problem), or the full output of the Net-SSLeay test suite if
the problem relates to a test failure;

=item *

your operating system name and version;

=item *

the output of C<perl -V>;

=item *

the version of Net-SSLeay you are using;

=item *

the version of OpenSSL or LibreSSL you are using.

=back

=head1 AUTHORS

Originally written by Chris Novakovic.

Maintained by Chris Novakovic, Tuure Vartiainen and Heikki Vatiainen.

=head1 COPYRIGHT AND LICENSE

Copyright 2020- Chris Novakovic <chris@chrisn.me.uk>.

Copyright 2020- Tuure Vartiainen <vartiait@radiatorsoftware.com>.

Copyright 2020- Heikki Vatiainen <hvn@radiatorsoftware.com>.

This module is released under the terms of the Artistic License 2.0. For
details, see the C<LICENSE> file distributed with Net-SSLeay's source code.

=cut
