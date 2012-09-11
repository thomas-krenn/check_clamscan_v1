#!/usr/bin/perl
# check_clam_scan: Nagios/Icinga plugin to check status of
# clam anti virus scanner
#
# Copyright (C) 2012 Thomas-Krenn.AG,
# For a list of contributors see changelog.txt
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>.
#
################################################################################
# The following guides provide helpful information if you want to extend this
# script:
#   http://nagiosplug.sourceforge.net/developer-guidelines.html (plug-in
#                  development guidelines)
################################################################################

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);#case sensitive

our $CLAMSCAN;

sub getVersion{
	
}
sub getUsage{
	
}
sub getHelp{
	
}
sub checkClamscanBin{
	my $clamBin = `which clamscan`;
	if($clamBin =~ m/clamscan/){
		return $clamBin;
	}
	return '';
}


MAIN: {
	
	#First, check for clamscan binary
	my $clamBin = checkClamscanBin();
	if($clamBin ne ''){
		$CLAMSCAN = $clamBin;
	}
	else{
		print "Error: Could not find clamscan binary with 'which clamscan'.\n";
		exit(3);
	}
	my $verbosity = 0;
	#Parse command line options
	if( !(Getopt::Long::GetOptions(
		'h|help'	=>
		sub{print getVersion();
				print  "\n";
				print getUsage();
				print "\n";
				print getHelp()."\n";
				exit(0);
		},
		'V|version'	=>
		sub{print getVersion()."\n";
				exit(0);
		},
		'v|verbosity'	=>	\$verbosity,
		'vv'			=> sub{$verbosity=2},
		'vvv'			=> sub{$verbosity=3},
	))){
		print get_usage()."\n";
		exit(1);
	}
}