#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Std;
use Net::SNMP;

my $program_name = "check_windows_processes";
my $program_version = "v0.1b";

# connection timeout value
my $timeout = 30;

# snmptranslate -On hrSWRunName
my $oid_proclist = '.1.3.6.1.2.1.25.4.2.1.2';

# Nagios specific return values
my $retval = {
        OK => 0,
        WARNING => 1,
        CRITICAL => 2,
        UNKNOWN => 3
};

sub usage {
        print @_ if @_;
        print <<"EOF";
Usage: $program_name -H <hostname|ip address> -C <SNMP community> -P <process1,process2,process3...>

  -H    Hostname or IP address of the monitored host
  -C    SNMP Community
  -P    Comma separated list of Windows processes to check
  -l    Long output, includes process names and instance count
  -f    Include performance data to generate graphs
  -h    Display this help and exit

EOF
	print "$program_name $program_version is released under the same license as Perl itself" unless @_;
        exit $retval->{UNKNOWN};
}

my %opts;

# populate command line options
getopts('H:C:P:flh', \%opts);

usage if defined $opts{h};
usage("Enter a hostname or an IP!\n") unless defined $opts{H};
usage("Enter SNMP community!\n") unless defined $opts{C};
usage("Enter Windows process list!\n") unless defined $opts{P};

my $hostname = $opts{H};                # Windows host name
my $community = $opts{C};               # SNMP community string
my $proc_list = $opts{P};               # sqlservr.exe,sqlwriter.exe,sqlbrowser.exe
my $flag_perf_data = $opts{f};          # flag for performance data
my $flag_long_output = $opts{l};        # flag for longer output

# list of processes to be monitored
my @processes = split /,\s*/, lc $proc_list;

my %angoor;
@angoor{@processes} = ();

# timeout handler
$SIG{ALRM} = sub {
        print "Connection timed out.  You may want to increase timeout value (current: $timeout)";
        exit $retval->{CRITICAL};
};

# create a new session
my ($session, $error) = Net::SNMP->session (
        -hostname => $hostname,
        -community => $community,
        -timeout => $timeout,
);

# session error, exit
unless (defined $session) {
        print "CRITICAL - $error";
        exit $retval->{CRITICAL};
}

my $result;
my @all_processes;

# repeated SNMP get-next-request
if (defined ($result = $session->get_table(-baseoid => $oid_proclist))) {
        for ($session->var_bind_names()) {
                push @all_processes, lc $result->{"$_"};
        }
} else {
        print "CRITICAL - ", $session->error();
        exit $retval->{CRITICAL};
}

$session->close();

# get the instance count for monitored processes
for my $p (@all_processes) {
        if (exists ($angoor{$p})) {
                $angoor{$p}++;
        }
}

# the list of processes not running
my @missing = grep { ! defined $angoor{$_} } sort keys %angoor;

my ($msg, $perf_data);

# generate performance data for monitored processes
if ($flag_perf_data) {
        for my $k (keys %angoor) {
                if (defined $angoor{$k}) {
                        $perf_data .= "$k=$angoor{$k};;0;; ";
                } else {
                        $perf_data .= "$k=0;;0;; ";
                }
        }
}

if (@missing) {
        $msg = "CRITICAL: ";
        $msg .= scalar @missing == 1 ? "Process " : "Processes ";
        $msg .= join ", ", @missing;
        $msg .= " not running";
        $msg .= " | $perf_data" if $flag_perf_data;
        print $msg;
        exit $retval->{CRITICAL};
} else {
        if ($flag_long_output) {
                $msg = "OK: ";
                $msg .= scalar @processes == 1 ? "Process " : "Processes ";
                $msg .= join ", ", map { "$_($angoor{$_})" } keys %angoor if $flag_long_output;
                $msg .= " are running";
        } else {
                $msg = "Processes OK";
        }
        $msg .= " | $perf_data" if $flag_perf_data;
        print $msg;
        exit $retval->{OK};
}

__END__
