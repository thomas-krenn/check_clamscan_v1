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
use Proc::ProcessTable;#check if scanner is running
use File::stat;
use Switch;
use Date::Calc qw(Delta_Days);

our $CLAMSCAN;#path to clamscan binary
#warning and critical threshold levels
our %PERF_THRESHOLDS = (
	scan_interval => ['2','5'], #days between scans
);


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
sub clamIsRunning{
	my $scanDir = quotemeta(shift);#the scanned directory
	my $t = new Proc::ProcessTable;
	foreach my $p ( @{$t->table} ){
		if($p->cmndline =~ m/^clamscan.+$scanDir/){
			return(1,$p->pid,scalar(localtime($p->start)));
		}
	}
	return (0,0,0);
}

sub parseClamLog{
	my $clamLog = shift;
	my %scanStat;
	open(my $fd, "<", $clamLog)
    	or die "Error: Cannot open < $clamLog: $!";
	
	my $pattern = "----------- SCAN SUMMARY -----------";
	my $found;
	while(<$fd>){
		my $line = $_;
		chomp($line);
		#Check if scan summary is found
		if($line eq $pattern){
			$found = 1;
			next;
		}
		#From summary on use status of scan
		#Split at : and use values after it
		#Lower key and substitute whitespaces
		if($found){
			my @stat = split(': ',$line);
			$stat[0] = lc $stat[0];
			$stat[0] =~ s/\s/\_/g;
			$scanStat{$stat[0]} = $stat[1];
		}		
	}
	return %scanStat;
}

sub getLastModified{
	my $clamLog = shift;
	my @logStat = stat($clamLog);
	#index 9 is mtime of stat
	my @mtime = localtime($logStat[0][9]);
	my @today = localtime;
	my $dD = Delta_Days($today[5],$today[4],$today[3],
						$mtime[5],$mtime[4],$mtime[3]);
	return $dD;
}

sub checkThlds{
	my @warnThlds = @{(shift)};
	my @critThls = @{(shift)};
	my %perfData = %{(shift)};
	
	my $i = 0;
	if(@warnThlds){
		@warnThlds = split(/,/, join(',', @warnThlds));
		for ($i = 0; $i < @warnThlds; $i++){
			#everything, except that values that sould stay default, get new values
			if($warnThlds[$i] ne 'd'){
				switch($i){
					case 0 {$PERF_THRESHOLDS{'scan_interval'}[0] = $warnThlds[$i]};
				}					
			}		
		}			
	}
	if(@critThls){
		@critThls = split(/,/, join(',', @critThls));
		for ($i = 0; $i < @critThls; $i++){
			if($critThls[$i] ne 'd'){
				switch($i){
					case 0 {$PERF_THRESHOLDS{'scan_interval'}[1] = $critThls[$i]};
				}
			}		
		}			
	}
	#start with OK
	my @statusLevel = ("OK");
	my @warnSens = ();#warning sensors
	my @critSens = ();#crit sensors
	foreach my $k (keys %perfData){
		if(exists $PERF_THRESHOLDS{$k}){
			#warning level
			if($perfData{$k} >= $PERF_THRESHOLDS{$k}[0]){
				$statusLevel[0] = "Warning";
				push(@warnSens,$k);
			}
			#critical level
			if($perfData{$k} >= $PERF_THRESHOLDS{$k}[1]){
				$statusLevel[0] = "Critical";
				pop(@critSens);#as it is critical, remove it from warning
				push(@critSens,$k);
			}
		}		
	}
	push(@statusLevel,\@warnSens);
	push(@statusLevel,\@critSens);
	return \@statusLevel;
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
	my $verbosity = 0;#verbose levels
	my $scanDir;#dirextory to be scanned
	my $clamLog;#log of clamscan
	my $scanInterval;#interval of clam scans
	my @warnThlds = ();#change thresholds for performance data
	my @critThlds = ();
	
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
		'sd|scandir=s'	=> \$scanDir,
		'l|log=s'	=> \$clamLog,
		'si|scaninterval=i'	=> \$scanInterval,
	))){
		print getUsage()."\n";
		exit(1);
	}
	if(@ARGV){
		#we don't want any unused command line arguments
		print getUsage()."\n";
		exit(3);
	}
	
	#the scanned directory is not given
	if(not defined $scanDir){
		print "Error: Scanned directory by clamscan is required.\n";
		print getUsage()."\n";
		exit(3);
	}
	
	#the clam log file is not given
	if(not defined $clamLog){
		print "Error: Clam log file is required.\n";
		print getUsage()."\n";
		exit(3);
	}
	
	#remove trailing slash if present
	if((substr $scanDir,-1,1) eq '/'){
		chop $scanDir;
	}
	my($ret,$pid,$start) = clamIsRunning($scanDir);
	if($ret eq 1 && $pid ne 0){
		print "Info: clamscan started at $start and is running with pid $pid.\n";
		exit(3);#TODO Correct exit code?
	}
	
	#Start checking status of clamscan
	my $exitCode = 0;
	my %scanStat = parseClamLog($clamLog);
	$scanStat{'scan_interval'} = getLastModified($clamLog);

	#check thresholds
	my $statusLevel = checkThlds(\@warnThlds,\@warnThlds,\%scanStat);
	#check return values of threshold function
	if($statusLevel->[0] eq "Critical"){
		$exitCode = 2;#Critical
	}
	if($statusLevel->[0] eq "Warning"){
		$exitCode = 1;#Warning
	}
	
}