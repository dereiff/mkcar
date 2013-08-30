#!/usr/local/bin/perl -w

# Author: Andrey N. Groshev aka GreenX. Begin in 2008 year. greenx[at]yandex[dot]ru
# under Public Domain license or beerware :)

use 5.012;
use strict;
use warnings FATAL => qw(uninitialized);
use feature "switch";
use Math::BigInt;
use Net::IP;
use autodie;
#use re 'debug';
$|=1;
my $DEBUG=1;
my $VERYDEBUG=0;
# MagicName
my $mn='-mkcar';

######################################################################
###                                                                ###
###                 V A R I A B L E S                              ###
###                                                                ###
######################################################################
print "\nFound the tools and may be their command lines:\n--------------------------------------\n" if $DEBUG;
my $ngctl = `whereis -qb ngctl` || die "Can't find ngctl!";
chomp($ngctl);
my $nghook = `whereis -qb nghook` || die "Can't find nghook!";
chomp($nghook);
my $tcpdump = `whereis -qb tcpdump` || die "Can't find tcpdump!";
chomp($tcpdump);
my $mecho = `whereis -qb echo` || die "Can't find echo!";
chomp($mecho);
$ngctl.=" -d" if $DEBUG;
$ngctl=~ s/d/dd/ if $VERYDEBUG;
$ngctl.=" -f - ";
$tcpdump.=" -ddd -s0 ";

print "\tngctl=$ngctl\n" if $DEBUG;
print "\tnghook=$nghook\n" if $DEBUG;
print "\ttcpdump=$tcpdump\n" if $DEBUG;
print "\techo=$mecho\n" if $DEBUG;

my ($lonode,$lohook,$hinode,$hihook);
my $l_in_filter="not ip";
my $u_in_filter="not ip";
my @cars=();

#var for netflow
my $netflow_ip;
my $netflow_itimeout=15;
my $netflow_atimeout=30;


##############################################################
###                                                        ###
###                        SUBROUTINES                     ###
###                                                        ###
##############################################################

sub parseconfig(\@)
{
my @config=@{$_[0]};
my $tmpline;
my $cl=0;
while (@config) {
    $tmpline=shift(@config);
    $cl++;
    chomp($tmpline);
    $tmpline=~tr/A-Z/a-z/;
    given ($tmpline) {
	when ($tmpline=~/^lohook\s+(.*):(.*)/)	{
	    if(defined($1) && defined($2)){
		$lonode=$1;
		$lohook=$2;
		`$ngctl show $1:`|| die "Node $1 not exist!\n";
		print "Lohook:\t\t$cl:$1:$2<-\n" if $DEBUG;
		}
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^hihook\s+(.*):(.*)/)	{
	    if(defined($1) && defined($2)){
		$hinode=$1;
		$hihook=$2;
		`$ngctl show $1:`|| die "Node $1 not exist!\n";
		print "Hihook:\t\t$cl:$1:$2<-\n" if $DEBUG;
		}
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^netflow_ip\s+(\d+\.\d+\.\d+\.\d+:\d+)/) {
	    if(defined($1)){ $netflow_ip=$1; print "netflow ip:\t$cl:$1\n" if $DEBUG }
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^netflow_atimeout\s+(.*)/) {
	    if(defined($1)){ $netflow_atimeout=$1; print "nf atimeout:\t$cl:$1\n" if $DEBUG }
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^netflow_itimeout\s+(.*)/) {
	    if(defined($1)){ $netflow_itimeout=$1; print "nf itimeout:\t$cl:$1\n" if $DEBUG }
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^nocar\s+(to|from)\s+(.*)/)	{
	    print "Work with line\t$cl:$tmpline\n" if $DEBUG;
	    if(defined($1) && defined($2)) {
		foreach my $i (split(/\s+/,$2)) {
		    #stupid check
		    my $progtmp=`$tcpdump src net $i 2>&1`;
		    my $srcadd=" or src net $i";
		    my $dstadd=" or dst net $i";
		    if($?!=0) {
			print "Ignor errfiltr:\t$cl:$i\t $progtmp";
		    }else{
			if($1 eq 'from'){
			    $l_in_filter.=$srcadd;
			    $u_in_filter.=$dstadd;
			}else{
			    $l_in_filter.=$dstadd;
			    $u_in_filter.=$srcadd;
			    }
			}
		    }
		}
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^car\s+(\d+)([gmk]?)\s+(\d+)([gmk]?)\s+(to|from)\s+(.*)/)	{
	    print "Work with line\t$cl:$_\n" if $DEBUG;
	    if(defined($1) && defined($2) && defined($3) && defined($4) && defined($5) && defined($6))
	    {
		my $direct=$5;

		my $dspeed=$1;
		if	($2 eq 'g')	{$dspeed*=1024*1024*1024}
		elsif	($2 eq 'm')	{$dspeed*=1024*1024}
		elsif	($2 eq 'k')	{$dspeed*=1024};

		my $uspeed=$3;
		if	($4 eq 'g')	{$uspeed*=1024*1024*1024}
		elsif	($4 eq 'm')	{$uspeed*=1024*1024}
		elsif	($4 eq 'k')	{$uspeed*=1024};

		# limits by ng_car
		die "$cl:Speed more 1_000_000_000 bps !\n" if ($dspeed > 1_000_000_000 || $uspeed > 1_000_000_000);
		#stupid check
		my @tmpfilter=();
		foreach my $i (split(/\s+/,$6)){
			if (my ($ip) = new Net::IP ($i)) {
			print "Added ->>$i<<--\n" if $VERYDEBUG;
			push(@tmpfilter,$ip);
			}
			else {
			print "Ignor errfiltr:\t$cl:$i\n";
			}
		}
		if ($#tmpfilter!=-1 ) {push(@cars,$dspeed,$uspeed,$direct,[@tmpfilter])};
		}
	    else {die "$cl:unexpected error\n"};
	    }
	when ($tmpline=~/^$|^#/)		{ print "Comment:\t$cl:$_<-\n" if $DEBUG }
	default { print "X.3.line ignor:\t$cl:$_\n" }
	} # end given
    } #end while
} # end parseconfig()


sub set_speed($$$){
# cbs = cir * 1 byte / 8 bites * 1.5 (RTT = Round-trip delay time)
# ebs = cbs * 2
my $tmpstr="msg $_[0]: setconf { ";
$tmpstr.="downstream={ cir=$_[1] cbs=".int($_[1]*3/16)." ebs=".int($_[1]*6/16)." greenAction=1 yellowAction=1 redAction=2 mode=3 } ";
$tmpstr.="  upstream={ cir=$_[2] cbs=".int($_[2]*3/16)." ebs=".int($_[2]*6/16)." greenAction=1 yellowAction=1 redAction=2 mode=3 }";
$tmpstr.=" }\n";
print $tmpstr if $VERYDEBUG;
return $tmpstr;
} # end set_speed function

sub genprog($$$$$){
my @progtmp;
chomp(@progtmp=`$tcpdump "$_[4]"`);
my ($tmpstr)="msg $_[0]: setprogram { thisHook=\"$_[1]\" ifMatch=\"$_[2]\" ifNotMatch=\"$_[3]\" bpf_prog_len=".shift(@progtmp)." bpf_prog=[ ";
while (@progtmp) {$tmpstr.=sprintf("{ code=%u jt=%u jf=%u k=%u } ", split(/\s+/,shift(@progtmp)))}
$tmpstr.="] }\n";
return $tmpstr;
} # end genprog function

sub gen_two_prog($$$$$$$$$){
my ($l_tmp,$u_tmp);
while (my $k = shift @{$_[8]}) {
    $l_tmp.="ether[".(($_[7] eq 'to') ? 30:26).":4]".(($k->prefixlen!=32)?" & ".$k->hexmask():"")." = ".$k->intip();
    $u_tmp.="ether[".(($_[7] eq 'to') ? 26:30).":4]".(($k->prefixlen!=32)?" & ".$k->hexmask():"")." = ".$k->intip();
    if (scalar @{$_[8]}!=0) {
	$l_tmp.=" or ";
	$u_tmp.=" or ";
	}
    }
print "Hook:".$_[1]." have filter:".$l_tmp."\nHook:".$_[4]." have filter:".$u_tmp."\n" if $VERYDEBUG;
my $l_str=genprog($_[0],$_[1],$_[2],$_[3],$l_tmp);
my $u_str=genprog($_[0],$_[4],$_[5],$_[6],$u_tmp);
print "\n\$l_str:".$l_str."\n" if $VERYDEBUG;
print "\n\$u_str:".$u_str."\n" if $VERYDEBUG;
return $l_str.$u_str;
} # end gen_two_prog function

sub genconf2ng(){
######################################################################
# NOTE
#
# Names of hooks:
# l_... resive data from low layer
# u_... resive data from up layer
print "\nGenerate a config for ngctl\n--------------------------------------\n" if $DEBUG;
my $hin=0; #hook index
my $ng_line;
$ng_line.="mkpeer split dummy mixed\n";
$ng_line.="name .:dummy l_sp".$mn."\n";
$ng_line.="mkpeer l_sp".$mn.": bpf out l_in\n";
$ng_line.="name l_sp".$mn.":out mainbpf".$mn."\n";
$ng_line.="mkpeer l_sp".$mn.": netflow in out0\n";
$ng_line.="name l_sp".$mn.":in netflow".$mn."\n";
$ng_line.="mkpeer netflow".$mn.": one2many iface0 one\n";
$ng_line.="name netflow".$mn.":iface0 u_o2m".$mn."\n";
$ng_line.="mkpeer netflow".$mn.": ksocket export inet/dgram/udp\n";
$ng_line.="name netflow".$mn.":export ksocket".$mn."\n";
$ng_line.="msg ksocket".$mn.": connect inet/".$netflow_ip."\n";
$ng_line.="connect mainbpf".$mn.": u_o2m".$mn.": u_out many".$hin."\n";
$ng_line.="mkpeer mainbpf".$mn.": split u_in out\n";
$ng_line.="name mainbpf".$mn.":u_in u_sp".$mn."\n";
$ng_line.="mkpeer mainbpf".$mn.": one2many l_out many".$hin."\n";
$ng_line.="name mainbpf".$mn.":l_out l_o2m".$mn."\n";
$ng_line.="connect l_o2m".$mn.": netflow".$mn.": one iface1\n";
$ng_line.="connect u_sp".$mn.": netflow".$mn.": in out1\n";
$ng_line.="msg netflow".$mn.": settimeouts { inactive = $netflow_itimeout active = $netflow_atimeout }\n";

$ng_line.=genprog("mainbpf".$mn,"l_in","l_out","u".$hin,$l_in_filter);
$ng_line.=genprog("mainbpf".$mn,"u_in","u_out","l".$hin,$u_in_filter);

# begin create car's
while (@cars){
    my ($dspeed,$uspeed,$direct,$filters) = splice (@cars,0,4);
    $ng_line.="mkpeer mainbpf".$mn.": split lo".$hin." in\n";
    $ng_line.="name mainbpf".$mn.":lo".$hin." l".$hin."sp\n";
    $ng_line.="mkpeer mainbpf".$mn.": split uo".$hin." in\n";
    $ng_line.="name mainbpf".$mn.":uo".$hin." u".$hin."sp\n";
    $ng_line.="mkpeer l".$hin."sp: car mixed lower\n";
    $ng_line.="name l".$hin."sp:mixed car".$hin."\n";
    $ng_line.="connect car".$hin.": u".$hin."sp: upper mixed\n";
    $ng_line.="connect l".$hin."sp: u_o2m".$mn.": out many".($hin+1)."\n";
    $ng_line.="connect u".$hin."sp: l_o2m".$mn.": out many".($hin+1)."\n";
    $ng_line.="connect mainbpf".$mn.": mainbpf".$mn.": l".$hin." u".$hin."\n";
    $ng_line.=gen_two_prog(	"mainbpf".$mn,
				"l".$hin, 	"lo".$hin,	(@cars)?"u".($hin+1):"l_out",
				"u".$hin,	"uo".$hin,	(@cars)?"l".($hin+1):"u_out",
				$direct,$filters);
    $ng_line.=set_speed("car".$hin,$dspeed,$uspeed);
    $hin++;
    if ($DEBUG && ($hin % 10) == 0) { print "." };
}
# end create cars.

if ($VERYDEBUG) {
    print "\nCommands for ngctl\n--------------------------------------\n";
    my $i=0;
    while($ng_line =~ /([^\n]+)\n?/g){
        print ++$i.":\t $1\n";
    }
}
return $ng_line;
}

######################################################################
###                                                                ###
###                           MAIN PROG                            ###
###                                                                ###
######################################################################

print "\nSearch and parsing the config\n--------------------------------------\n" if $DEBUG;
open (my $CONFIG, '<',"mkcar.conf") or die $!;
my @config=<$CONFIG>;
close ($CONFIG);
parseconfig(@config);
die "Error: No one car (нехуй делать), EXIT!\n" if !@cars ;
if($DEBUG){
    print "
Igogo:\n-----------------------------------------------------------
Filter on l_in hook:$l_in_filter
Filter on u_in hook:$u_in_filter
Numer of CAR's\t:".(($#cars+1)/4)."\n";
    if($VERYDEBUG){
	while (my ($index,$col) = each (@cars)){
	    if( ($index+1)%4==0) {
		foreach my $fil (@{$col}) {
		    print "CIRD:".$fil->ip()."/".$fil->prefixlen()."\t"
		}
		print "\n"
	    }
	    else {print $col."\t"}
	}
    }
}
my $ng_cfg_line=genconf2ng(); #without connected lines
!system("$mecho \'$ng_cfg_line\'|$ngctl") || die "Error while sending config command string to ngctl! (Чёта не робит)\n";
$ng_cfg_line="disconnect dummy
connect ".$lonode.": l_sp".$mn.": $lohook mixed
connect ".$hinode.": u_sp".$mn.": $hihook mixed";
!system("$mecho \'$ng_cfg_line\'|$ngctl") || die "Error connecting to ethernet interface!\n";
