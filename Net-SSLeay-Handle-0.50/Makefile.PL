# $Id: Makefile.PL,v 1.2 2002/06/07 12:43:42 sampo Exp $
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::SSLeay::Handle',
    'VERSION_FROM'	=> 'Handle.pm', # finds $VERSION
);
